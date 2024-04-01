package scan

import (
	"fmt"
	"slices"

	"github.com/samber/lo"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
)

const (
	AdvisoriesSetResolved           = "resolved"
	AdvisoriesSetAll                = "all"
	AdvisoriesSetConcluded          = "concluded"
	AdvisoriesSetConcludedOrPending = "concluded-or-pending"
)

var ValidAdvisoriesSets = []string{AdvisoriesSetResolved, AdvisoriesSetAll, AdvisoriesSetConcluded, AdvisoriesSetConcludedOrPending}

// FilterWithAdvisories filters the findings in the result based on the advisories for the target APK.
func FilterWithAdvisories(result Result, advisoryDocIndices []*configs.Index[v2.Document], advisoryFilterSet string) ([]Finding, error) {
	if advisoryDocIndices == nil {
		return nil, fmt.Errorf("advisory configs cannot be nil")
	}

	var documents []v2.Document
	for _, index := range advisoryDocIndices {
		docs := index.Select().WhereName(result.TargetAPK.Origin()).Configurations()
		documents = append(documents, docs...)
	}

	// TODO: Should we error out if we end up with multiple documents for a single package?

	if len(documents) == 0 {
		// No advisory configs for this package, so we know we wouldn't be able to filter anything.
		return result.Findings, nil
	}

	// Use a copy of the findings, so we don't mutate the original result.
	filteredFindings := slices.Clone(result.Findings)

	for _, document := range documents {
		packageAdvisories := document.Advisories

		switch advisoryFilterSet {
		case AdvisoriesSetAll:
			filteredFindings = filterFindingsWithAllAdvisories(filteredFindings, packageAdvisories)

		case AdvisoriesSetResolved:
			filteredFindings = filterFindingsWithResolvedAdvisories(filteredFindings, packageAdvisories, result.TargetAPK.Version)

		case AdvisoriesSetConcluded:
			filteredFindings = filterFindingsWithConcludedAdvisories(filteredFindings, packageAdvisories, result.TargetAPK.Version)

		case AdvisoriesSetConcludedOrPending:
			filteredFindings = filterFindingsWithConcludedOrPendingAdvisories(filteredFindings, packageAdvisories, result.TargetAPK.Version)

		default:
			return nil, fmt.Errorf("unknown advisory filter set: %s", advisoryFilterSet)
		}
	}

	return filteredFindings, nil
}

func filterFindingsWithAllAdvisories(findings []Finding, packageAdvisories v2.Advisories) []Finding {
	return lo.Filter(findings, func(finding Finding, _ int) bool {
		adv, ok := packageAdvisories.GetByVulnerability(finding.Vulnerability.ID)
		// If the advisory contains any events, filter it out!
		if ok && len(adv.Events) >= 1 {
			return false
		}

		// Also check any listed aliases
		for _, alias := range finding.Vulnerability.Aliases {
			adv, ok := packageAdvisories.GetByVulnerability(alias)
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

func filterFindingsWithResolvedAdvisories(findings []Finding, packageAdvisories v2.Advisories, currentPackageVersion string) []Finding {
	return lo.Filter(findings, func(finding Finding, _ int) bool {
		adv, ok := packageAdvisories.GetByVulnerability(finding.Vulnerability.ID)
		if ok && adv.ResolvedAtVersion(currentPackageVersion, finding.Package.Type) {
			return false
		}

		// Also check any listed aliases
		for _, alias := range finding.Vulnerability.Aliases {
			adv, ok := packageAdvisories.GetByVulnerability(alias)
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

func filterFindingsWithConcludedAdvisories(findings []Finding, packageAdvisories v2.Advisories, currentPackageVersion string) []Finding {
	return lo.Filter(findings, func(finding Finding, _ int) bool {
		adv, ok := packageAdvisories.GetByVulnerability(finding.Vulnerability.ID)
		if ok && adv.ConcludedAtVersion(currentPackageVersion, finding.Package.Type) {
			return false
		}

		// Also check any listed aliases
		for _, alias := range finding.Vulnerability.Aliases {
			adv, ok := packageAdvisories.GetByVulnerability(alias)
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

func filterFindingsWithConcludedOrPendingAdvisories(findings []Finding, packageAdvisories v2.Advisories, currentPackageVersion string) []Finding {
	return lo.Filter(findings, func(finding Finding, _ int) bool {
		adv, ok := packageAdvisories.GetByVulnerability(finding.Vulnerability.ID)
		if ok && adv.ConcludedOrPendingAtVersion(currentPackageVersion, finding.Package.Type) {
			return false
		}

		// Also check any listed aliases
		for _, alias := range finding.Vulnerability.Aliases {
			adv, ok := packageAdvisories.GetByVulnerability(alias)
			if !ok {
				continue
			}

			if adv.ConcludedOrPendingAtVersion(currentPackageVersion, finding.Package.Type) {
				return false
			}
		}

		return true
	})
}
