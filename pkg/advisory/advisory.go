package advisory

import (
	"fmt"
	"log"
	"sort"
	"time"

	"chainguard.dev/melange/pkg/build"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/pkg/errors"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	"github.com/wolfi-dev/wolfictl/pkg/vuln"
)

type CreateOptions struct {
	// The Index of package configs on which to operate.
	Index *configs.Index

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

	selection := options.Index.Select().WhereFilePath(path)
	if count := selection.Len(); count != 1 {
		return fmt.Errorf("can only operate on 1 config, but found %d configs at file path %q", count, path)
	}

	vulnID := options.Vuln
	advisoryEntry := options.InitialAdvisoryEntry
	if advisoryEntry == nil {
		return errors.New("cannot use nil advisory entry")
	}

	err := selection.UpdateAdvisories(func(cfg build.Configuration) (build.Advisories, error) {
		advisories := cfg.Advisories
		if _, existsAlready := advisories[vulnID]; existsAlready {
			return build.Advisories{}, fmt.Errorf("advisory already exists for %s", vulnID)
		}

		advisories[vulnID] = append(advisories[vulnID], *advisoryEntry)

		return advisories, nil
	})
	if err != nil {
		return fmt.Errorf("unable to create advisories entry in %q: %w", path, err)
	}

	return nil
}

type UpdateOptions struct {
	// The Index of package configs on which to operate.
	Index *configs.Index

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

	selection := options.Index.Select().WhereFilePath(path)
	if count := selection.Len(); count != 1 {
		return fmt.Errorf("can only update 1 config, but found %d configs at file path %q", count, path)
	}

	vulnID := options.Vuln
	advisoryEntry := options.NewAdvisoryEntry
	if advisoryEntry == nil {
		return errors.New("cannot use nil advisory entry")
	}

	err := selection.UpdateAdvisories(func(cfg build.Configuration) (build.Advisories, error) {
		advisories := cfg.Advisories
		if _, existsAlready := advisories[vulnID]; !existsAlready {
			return build.Advisories{}, fmt.Errorf("no advisory exists for %s", vulnID)
		}

		advisories[vulnID] = append(advisories[vulnID], *advisoryEntry)

		return advisories, nil
	})
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
	// The Index of package configs on which to operate.
	Index *configs.Index

	// VulnerabilitySearcher is how Discover searches for vulnerabilities to match to
	// packages.
	VulnerabilitySearcher vuln.Searcher
}

// Discover searches for new vulnerabilities that match packages in a config
// index, and adds new advisories to configs for vulnerabilities that haven't
// been noted yet.
func Discover(options DiscoverOptions) error {
	matches, err := options.VulnerabilitySearcher.AllVulnerabilities()
	if err != nil {
		return fmt.Errorf("unable to discover advisories: %w", err)
	}

	err = options.Index.Select().UpdateAdvisories(func(cfg build.Configuration) (build.Advisories, error) {
		matchesForPackage := matches[cfg.Package.Name]
		if len(matchesForPackage) == 0 {
			// nothing to update for this package
			return build.Advisories{}, configs.ErrSkip
		}

		//nolint:gocritic // rangeValCopy rule not worth it here
		for _, m := range matchesForPackage {
			if !m.CPE.VersionRange.Includes(cfg.Package.Version) {
				continue
			}

			vulnID := m.Vulnerability.ID
			_, exists := cfg.Advisories[vulnID]

			if exists {
				// TODO: Should we allow for updating existing advisories if previously read vuln
				// data has been updated?
				log.Printf("skipping advisory creation for %s in %q: advisory already exists", vulnID, cfg.Package.Name)
				continue
			}

			log.Printf("found new potential vulnerability for package %q: %s", cfg.Package.Name, vulnID)

			ts := time.Now()
			ac := build.AdvisoryContent{
				Timestamp: ts,
				Status:    vex.StatusUnderInvestigation,
				// TODO: Note the reported affected version range.
			}
			cfg.Advisories[vulnID] = append(cfg.Advisories[vulnID], ac)
		}

		return cfg.Advisories, nil
	})
	if err != nil {
		return err
	}

	return nil
}
