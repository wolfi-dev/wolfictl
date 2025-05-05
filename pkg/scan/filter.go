package scan

import (
	"context"
	"fmt"
	"slices"

	v2 "github.com/chainguard-dev/advisory-schema/pkg/advisory/v2"
	"github.com/samber/lo"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
)

const (
	AdvisoriesSetResolved  = "resolved"
	AdvisoriesSetAll       = "all"
	AdvisoriesSetConcluded = "concluded"
)

var ValidAdvisoriesSets = []string{AdvisoriesSetResolved, AdvisoriesSetAll, AdvisoriesSetConcluded}

// FilterWithAdvisories filters the findings in the result based on the advisories for the target APK.
func FilterWithAdvisories(ctx context.Context, result Result, advGetter advisory.Getter, advisoryFilterSet string) ([]Finding, error) {
	// TODO: consider using the context for more detailed logging of the filtering logic.

	if advGetter == nil {
		return nil, fmt.Errorf("advGetter cannot be nil")
	}

	// Use a copy of the findings, so we don't mutate the original result.
	filteredFindings := slices.Clone(result.Findings)

	// Check for advisories in both the result target's name and origin package (to handle subpackages)
	for _, name := range []string{result.TargetAPK.Name, result.TargetAPK.OriginPackageName} {
		packageAdvisories, err := advGetter.Advisories(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("getting advisories for package %q: %w", name, err)
		}

		switch advisoryFilterSet {
		case AdvisoriesSetAll:
			filteredFindings = filterFindingsWithAllAdvisories(filteredFindings, packageAdvisories)

		case AdvisoriesSetResolved:
			filteredFindings = filterFindingsWithResolvedAdvisories(filteredFindings, packageAdvisories, result.TargetAPK.Version)

		case AdvisoriesSetConcluded:
			filteredFindings = filterFindingsWithConcludedAdvisories(filteredFindings, packageAdvisories, result.TargetAPK.Version)

		default:
			return nil, fmt.Errorf("unknown advisory filter set: %s", advisoryFilterSet)
		}
	}

	return filteredFindings, nil
}

func filterFindingsWithAllAdvisories(findings []Finding, packageAdvisories []v2.PackageAdvisory) []Finding {
	if len(packageAdvisories) == 0 {
		return findings
	}

	advsByVulnID := advisory.MapByVulnID(packageAdvisories)
	for _, adv := range packageAdvisories {
		for _, alias := range adv.Aliases {
			advsByVulnID[alias] = &adv
		}
	}

	return lo.Filter(findings, func(finding Finding, _ int) bool {
		adv, ok := advsByVulnID[finding.Vulnerability.ID]
		if ok && len(adv.Events) >= 1 {
			// If the advisory contains any events, filter it out!
			return false
		}

		// Also check any listed aliases
		for _, alias := range finding.Vulnerability.Aliases {
			adv, ok := advsByVulnID[alias]
			if !ok {
				continue
			}

			if len(adv.Events) >= 1 {
				return false
			}
		}

		return true
	})
}

func filterFindingsWithResolvedAdvisories(findings []Finding, packageAdvisories []v2.PackageAdvisory, currentPackageVersion string) []Finding {
	if len(packageAdvisories) == 0 {
		return findings
	}

	advsByVulnID := advisory.MapByVulnID(packageAdvisories)

	return lo.Filter(findings, func(finding Finding, _ int) bool {
		adv, ok := advsByVulnID[finding.Vulnerability.ID]
		if ok && adv.ResolvedAtVersion(currentPackageVersion, finding.Package.Type) {
			return false
		}

		// Also check any listed aliases
		for _, alias := range finding.Vulnerability.Aliases {
			adv, ok := advsByVulnID[alias]
			if !ok {
				continue
			}

			if adv.ResolvedAtVersion(currentPackageVersion, finding.Package.Type) {
				return false
			}
		}

		return true
	})
}

func filterFindingsWithConcludedAdvisories(findings []Finding, packageAdvisories []v2.PackageAdvisory, currentPackageVersion string) []Finding {
	if len(packageAdvisories) == 0 {
		return findings
	}

	advsByVulnID := advisory.MapByVulnID(packageAdvisories)

	return lo.Filter(findings, func(finding Finding, _ int) bool {
		adv, ok := advsByVulnID[finding.Vulnerability.ID]
		if ok && adv.ConcludedAtVersion(currentPackageVersion, finding.Package.Type) {
			return false
		}

		// Also check any listed aliases
		for _, alias := range finding.Vulnerability.Aliases {
			adv, ok := advsByVulnID[alias]
			if !ok {
				continue
			}

			if adv.ConcludedAtVersion(currentPackageVersion, finding.Package.Type) {
				return false
			}
		}

		return true
	})
}
