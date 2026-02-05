package advisory

import (
	"context"
	"fmt"
	"net/http"
	"sort"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/apk/client"
	"chainguard.dev/melange/pkg/config"
	v2 "github.com/chainguard-dev/advisory-schema/pkg/advisory/v2"
	"github.com/samber/lo"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	"github.com/wolfi-dev/wolfictl/pkg/vuln"
)

type DiscoverOptions struct {
	// SelectedPackages is a list of packages to include in search. If empty, all
	// packages will be included in search.
	SelectedPackages []string

	// BuildCfgs is the Index of build configurations on which to operate.
	BuildCfgs *configs.Index[config.Configuration]

	// AdvisoryDocs is the Index of advisory documents on which to operate.
	AdvisoryDocs *configs.Index[v2.Document]

	// PackageRepositoryURL is the URL to the distro's package repository (e.g.
	// "https://packages.wolfi.dev/os").
	PackageRepositoryURL string

	// The Arches to select during discovery (e.g. "x86_64").
	Arches []string

	// VulnerabilityDetector is how Discover finds vulnerabilities for packages.
	VulnerabilityDetector vuln.Detector

	// VulnEvents is a channel of events that occur during vulnerability discovery.
	VulnEvents chan<- interface{}
}

// Discover searches for new vulnerabilities that match packages in a config
// index, and adds new advisories to configs for vulnerabilities that haven't
// been noted yet.
func Discover(ctx context.Context, opts DiscoverOptions) error {
	var packagesToLookup []string

	// If the user has specified a set of packages to search for, we'll only search
	// for those. This also helps us skip the cost of downloading APKINDEXes.
	if len(opts.SelectedPackages) >= 1 {
		packagesToLookup = opts.SelectedPackages
	} else {
		packageRepositoryURL := opts.PackageRepositoryURL
		if packageRepositoryURL == "" {
			return fmt.Errorf("package repository URL must be specified")
		}

		c := client.New(http.DefaultClient)
		var apkindexes []*apk.APKIndex
		for _, arch := range opts.Arches {
			idx, err := c.GetRemoteIndex(ctx, packageRepositoryURL, arch)
			if err != nil {
				return fmt.Errorf("getting APKINDEX for %s: %w", arch, err)
			}
			apkindexes = append(apkindexes, idx)
		}

		packagesToLookup = uniquePackageNamesFromAPKINDEXes(apkindexes)
	}

	for _, pkg := range packagesToLookup {
		if err := ctx.Err(); err != nil {
			return err
		}

		pkg := pkg
		err := opts.discoverMatchesForPackage(ctx, pkg)
		if err != nil {
			return err
		}
	}

	opts.VulnEvents <- vuln.EventMatchingFinished{}

	return nil
}

func (opts DiscoverOptions) discoverMatchesForPackage(ctx context.Context, pkg string) error {
	opts.VulnEvents <- vuln.EventPackageMatchingStarting{Package: pkg}

	matches, err := opts.VulnerabilityDetector.VulnerabilitiesForPackage(ctx, pkg)
	if ctx.Err() != nil {
		return err
	}
	if err != nil {
		opts.VulnEvents <- vuln.EventPackageMatchingError{Package: pkg, Err: err}
	}

	matches, err = opts.filterMatchesForPackage(pkg, matches)
	if err != nil {
		return fmt.Errorf("filtering vulnerability matches: %w", err)
	}

	opts.VulnEvents <- vuln.EventPackageMatchingFinished{Package: pkg, Matches: matches}

	for i := range matches {
		match := matches[i]
		err := Create(ctx, Request{
			Package: pkg,
			Aliases: []string{match.Vulnerability.ID},
			Event:   advisoryEventForNewDiscovery(match),
		}, CreateOptions{opts.AdvisoryDocs})
		if err != nil {
			return err
		}
	}

	return nil
}

func (opts DiscoverOptions) filterMatchesForPackage(pkg string, matches []vuln.Match) ([]vuln.Match, error) {
	buildCfgEntry, err := opts.BuildCfgs.Select().WhereName(pkg).First()
	if err != nil {
		return nil, fmt.Errorf("finding package %q among build configurations: %w", pkg, err)
	}
	buildCfg := buildCfgEntry.Configuration()

	var filteredMatches []vuln.Match

	for i := range matches {
		match := matches[i]
		if !match.CPEFound.VersionRange.Includes(buildCfg.Package.Version) {
			continue
		}

		vulnID := match.Vulnerability.ID

		// TODO: We shouldn't need to know about documents here, we should just have a
		//  query against the total dataset for this package-vuln pair.

		advisoryDocuments := opts.AdvisoryDocs.Select().WhereName(pkg)
		if advisoryDocuments.Len() == 0 {
			filteredMatches = append(filteredMatches, match)
			continue
		}

		// there's an existing advisories config

		advCfgEntry, _ := advisoryDocuments.First() //nolint:errcheck
		document := advCfgEntry.Configuration()
		if _, exists := document.Advisories.GetByVulnerability(vulnID); exists {
			// advisory already exists in config
			continue
		}

		filteredMatches = append(filteredMatches, match)
	}

	return filteredMatches, nil
}

func advisoryEventForNewDiscovery(match vuln.Match) v2.Event {
	return v2.Event{
		Timestamp: v2.Now(),
		Type:      v2.EventTypeDetection,
		Data: v2.Detection{
			Type: v2.DetectionTypeNVDAPI,
			Data: v2.DetectionNVDAPI{
				CPESearched: match.CPESearched.URI,
				CPEFound:    match.CPEFound.URI,
			},
		},
	}
}

func uniquePackageNamesFromAPKINDEXes(apkindexes []*apk.APKIndex) []string {
	packagesFound := make(map[string]struct{})

	for _, apkindex := range apkindexes {
		if apkindex == nil {
			continue
		}

		for _, pkg := range apkindex.Packages {
			if pkg.Origin == "" {
				// This case was caused by a bug in Melange early on, that has since been
				// resolved.
				continue
			}
			name := pkg.Origin

			// skip redundant recording of package name
			if _, ok := packagesFound[name]; ok {
				continue
			}

			packagesFound[name] = struct{}{}
		}
	}

	packagesToLookup := lo.Keys(packagesFound)
	sort.Strings(packagesToLookup)

	return packagesToLookup
}
