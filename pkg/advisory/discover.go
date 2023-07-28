package advisory

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"chainguard.dev/melange/pkg/config"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/samber/lo"
	"github.com/savioxavier/termlink"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	advisoryconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/index"
	"github.com/wolfi-dev/wolfictl/pkg/vuln"
	"gitlab.alpinelinux.org/alpine/go/repository"
	"golang.org/x/exp/slices"
)

type DiscoverOptions struct {
	// SelectedPackages is a list of packages to include in search. If empty, all packages will be included in search.
	SelectedPackages []string

	// BuildCfgs is the Index of build configurations on which to operate.
	BuildCfgs *configs.Index[config.Configuration]

	// AdvisoryCfgs is the Index of advisories on which to operate.
	AdvisoryCfgs *configs.Index[advisoryconfigs.Document]

	// PackageRepositoryURL is the URL to the distro's package repository (e.g. "https://packages.wolfi.dev/os").
	PackageRepositoryURL string

	// The Arches to select during discovery (e.g. "x86_64").
	Arches []string

	// VulnerabilityDetector is how Discover finds for vulnerabilities for packages.
	VulnerabilityDetector vuln.Detector
}

// Discover searches for new vulnerabilities that match packages in a config
// index, and adds new advisories to configs for vulnerabilities that haven't
// been noted yet.
func Discover(opts DiscoverOptions) error {
	ctx := context.Background()

	packageRepositoryURL := opts.PackageRepositoryURL
	if packageRepositoryURL == "" {
		return fmt.Errorf("package repository URL must be specified")
	}

	var apkindexes []*repository.ApkIndex
	for _, arch := range opts.Arches {
		apkindex, err := index.Index(arch, packageRepositoryURL)
		if err != nil {
			return fmt.Errorf("unable to get APKINDEX for arch %q: %w", arch, err)
		}
		apkindexes = append(apkindexes, apkindex)
	}

	packagesToLookup := determinePackagesToLookup(apkindexes, opts.SelectedPackages)

	vulnMatches, err := opts.VulnerabilityDetector.VulnerabilitiesForPackages(ctx, packagesToLookup...)
	if err != nil {
		return err
	}

	for _, pkg := range packagesToLookup {
		pkgVulnMatches := vulnMatches[pkg]

		err := processPkgVulnMatches(opts, pkg, pkgVulnMatches)
		if err != nil {
			return err
		}
	}

	return nil
}

func processPkgVulnMatches(opts DiscoverOptions, pkg string, matches []vuln.Match) error {
	buildCfgEntry, _ := opts.BuildCfgs.Select().WhereName(pkg).First() //nolint:errcheck
	buildCfg := buildCfgEntry.Configuration()

	for i := range matches {
		match := matches[i]
		if !match.CPE.VersionRange.Includes(buildCfg.Package.Version) {
			continue
		}

		advCfgEntries := opts.AdvisoryCfgs.Select().WhereName(pkg)
		vulnID := match.Vulnerability.ID
		if advCfgEntries.Len() == 0 {
			// create a brand-new advisory config

			err := createAdvisoryConfig(opts.AdvisoryCfgs, Request{
				Package:       pkg,
				Vulnerability: vulnID,
				Status:        vex.StatusUnderInvestigation,
				Timestamp:     time.Now(),
			})
			if err != nil {
				return fmt.Errorf("unable to record new advisory: %w", err)
			}

			continue
		}

		// there's an existing advisories config

		advCfgEntry, _ := advCfgEntries.First() //nolint:errcheck
		advCfg := advCfgEntry.Configuration()
		if _, ok := advCfg.Advisories[vulnID]; ok {
			// advisory already exists in config
			continue
		}

		log.Printf("🐛 new potential vulnerability for package %q: %s", advCfg.Package.Name, hyperlinkCVE(vulnID))

		u := advisoryconfigs.NewAdvisoriesSectionUpdater(func(cfg advisoryconfigs.Document) (advisoryconfigs.Advisories, error) {
			advisories := cfg.Advisories
			advisories[vulnID] = append(advisories[vulnID], advisoryEntryForNewDiscovery())

			return advisories, nil
		})

		err := advCfgEntry.Update(u)
		if err != nil {
			return err
		}
	}

	return nil
}

func advisoryEntryForNewDiscovery() advisoryconfigs.Entry {
	return advisoryconfigs.Entry{
		Timestamp: time.Now(),
		Status:    vex.StatusUnderInvestigation,
	}
}

func determinePackagesToLookup(apkindexes []*repository.ApkIndex, selectedPackageNames []string) []string {
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

			// skip package if we've specified a disjoint set of packages to search for
			if len(selectedPackageNames) >= 1 && !slices.Contains(selectedPackageNames, name) {
				continue
			}

			// skip redundant recording of package name
			if _, ok := packagesFound[name]; ok {
				continue
			}

			packagesFound[name] = struct{}{}
		}
	}

	log.Printf("🔎 discovered %d package(s) to search for in NVD", len(packagesFound))

	packagesToLookup := lo.Keys(packagesFound)
	sort.Strings(packagesToLookup)

	return packagesToLookup
}

var termSupportsHyperlinks = termlink.SupportsHyperlinks()

func hyperlinkCVE(id string) string {
	if !termSupportsHyperlinks {
		return id
	}

	return termlink.Link(id, fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", id))
}
