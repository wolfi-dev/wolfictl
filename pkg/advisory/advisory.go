package advisory

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"chainguard.dev/melange/pkg/build"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/pkg/errors"
	"github.com/samber/lo"
	"github.com/savioxavier/termlink"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	buildconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/build"
	"github.com/wolfi-dev/wolfictl/pkg/index"
	"github.com/wolfi-dev/wolfictl/pkg/vuln"
	"gitlab.alpinelinux.org/alpine/go/repository"
)

type CreateOptions struct {
	// BuildCfgs is the Index of build configurations on which to operate.
	BuildCfgs *configs.Index[build.Configuration]

	// Pathname is the filepath for the configuration to which Create will add the
	// new advisory.
	Pathname string

	// Vuln is the vulnerability ID used to name the new advisory.
	Vuln string

	// InitialAdvisoryEntry is the entry that will be added to the new advisory.
	InitialAdvisoryEntry *build.AdvisoryContent
}

// Create creates a new advisory in the `advisories` section of the configuration
// at the provided path.
func Create(options CreateOptions) error {
	path := options.Pathname

	selection := options.BuildCfgs.Select().WhereFilePath(path)
	if count := selection.Len(); count != 1 {
		return fmt.Errorf("can only operate on 1 config, but found %d configs at file path %q", count, path)
	}

	vulnID := options.Vuln
	advisoryEntry := options.InitialAdvisoryEntry
	if advisoryEntry == nil {
		return errors.New("cannot use nil advisory entry")
	}

	updateAdvisories := buildconfigs.NewAdvisoriesSectionUpdater(func(cfg build.Configuration) (build.Advisories, error) {
		advisories := cfg.Advisories
		if _, existsAlready := advisories[vulnID]; existsAlready {
			return build.Advisories{}, fmt.Errorf("advisory already exists for %s", vulnID)
		}

		advisories[vulnID] = append(advisories[vulnID], *advisoryEntry)

		return advisories, nil
	})

	err := selection.UpdateEntries(updateAdvisories)
	if err != nil {
		return fmt.Errorf("unable to create advisories entry in %q: %w", path, err)
	}

	return nil
}

type UpdateOptions struct {
	// BuildCfgs is the Index of build configurations on which to operate.
	BuildCfgs *configs.Index[build.Configuration]

	// Pathname is the filepath for the configuration in which Update will append the
	// new advisory entry.
	Pathname string

	// Vuln is the vulnerability ID for the advisory to update.
	Vuln string

	// NewAdvisoryEntry is the entry that will be added to the advisory.
	NewAdvisoryEntry *build.AdvisoryContent
}

// Update adds a new entry to an existing advisory (named by the vuln parameter)
// in the configuration at the provided path.
func Update(options UpdateOptions) error {
	path := options.Pathname

	selection := options.BuildCfgs.Select().WhereFilePath(path)
	if count := selection.Len(); count != 1 {
		return fmt.Errorf("can only update 1 config, but found %d configs at file path %q", count, path)
	}

	vulnID := options.Vuln
	advisoryEntry := options.NewAdvisoryEntry
	if advisoryEntry == nil {
		return errors.New("cannot use nil advisory entry")
	}

	updateAdvisories := buildconfigs.NewAdvisoriesSectionUpdater(func(cfg build.Configuration) (build.Advisories, error) {
		advisories := cfg.Advisories
		if _, existsAlready := advisories[vulnID]; !existsAlready {
			return build.Advisories{}, fmt.Errorf("no advisory exists for %s", vulnID)
		}

		advisories[vulnID] = append(advisories[vulnID], *advisoryEntry)

		return advisories, nil
	})

	err := selection.UpdateEntries(updateAdvisories)
	if err != nil {
		return fmt.Errorf("unable to add entry for advisory %q in %q: %w", vulnID, path, err)
	}

	return nil
}

// Latest returns the latest entry among the given set of entries for an
// advisory. If there are no entries, Latest returns nil.
func Latest(entries []build.AdvisoryContent) *build.AdvisoryContent {
	if len(entries) == 0 {
		return nil
	}

	// Try to respect the caller's sort order, and make changes only in this scope.
	items := make([]build.AdvisoryContent, len(entries))
	copy(items, entries)

	sort.SliceStable(items, func(i, j int) bool {
		return items[i].Timestamp.Before(items[j].Timestamp)
	})

	latestEntry := items[len(items)-1]
	return &latestEntry
}

type DiscoverOptions struct {
	// BuildCfgs is the Index of build configurations on which to operate.
	BuildCfgs *configs.Index[build.Configuration]

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

	var apkindexes []*repository.ApkIndex
	for _, arch := range opts.Arches {
		apkindex, err := index.Index(arch, opts.PackageRepositoryURL)
		if err != nil {
			return fmt.Errorf("unable to get APKINDEX for arch %q: %w", arch, err)
		}
		apkindexes = append(apkindexes, apkindex)
	}

	packagesToLookup := determinePackagesToLookup(apkindexes, opts.BuildCfgs)

	vulnMatches, err := opts.VulnerabilityDetector.VulnerabilitiesForPackages(ctx, packagesToLookup...)
	if err != nil {
		return err
	}

	updateAdvisories := buildconfigs.NewAdvisoriesSectionUpdater(func(cfg build.Configuration) (build.Advisories, error) {
		matchesForPackage := vulnMatches[cfg.Package.Name]
		if len(vulnMatches) == 0 {
			// nothing to update for this package
			return build.Advisories{}, configs.ErrSkip
		}

		// Keep track of whether we'll need to add advisories for new matches. If not,
		// we won't touch the file.
		anyNewMatches := false

		//nolint:gocritic // rangeValCopy rule not worth it here
		for _, m := range matchesForPackage {
			if !m.CPE.VersionRange.Includes(cfg.Package.Version) {
				continue
			}

			vulnID := m.Vulnerability.ID
			_, exists := cfg.Advisories[vulnID]

			if exists {
				// TODO: Should we allow for updating existing advisories if previously read vuln
				//  data has been updated?

				continue
			}

			anyNewMatches = true
			log.Printf("🐛 new potential vulnerability for package %q: %s", cfg.Package.Name, hyperlinkCVE(vulnID))

			ts := time.Now()
			ac := build.AdvisoryContent{
				Timestamp: ts,
				Status:    vex.StatusUnderInvestigation,
				// TODO: Note the reported affected version range.
			}
			cfg.Advisories[vulnID] = append(cfg.Advisories[vulnID], ac)
		}

		if !anyNewMatches {
			return build.Advisories{}, configs.ErrSkip
		}

		return cfg.Advisories, nil
	})

	err = opts.BuildCfgs.Select().UpdateEntries(updateAdvisories)
	if err != nil {
		return err
	}

	return nil
}

func determinePackagesToLookup(apkindexes []*repository.ApkIndex, buildCfgs *configs.Index[build.Configuration]) []string {
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

			// skip package if it hasn't been included among the given package configs
			isInConfigsIndex := buildCfgs.Select().WhereName(name).Len() != 0
			if !isInConfigsIndex {
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
