package scan

import (
	"fmt"

	"github.com/samber/lo"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
)

const (
	AdvisoriesSetResolved = "resolved"
	AdvisoriesSetAll      = "all"
)

var ValidAdvisoriesSets = []string{AdvisoriesSetResolved, AdvisoriesSetAll}

// FilterWithAdvisories filters the findings in the result based on the advisories for the target APK.
func FilterWithAdvisories(result *Result, advisoryDocIndices []*configs.Index[v2.Document], advisoryFilterSet string) ([]*Finding, error) {
	if result == nil {
		return nil, fmt.Errorf("result cannot be nil")
	}

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

	// Use a copy of the findings so we don't mutate the original result.
	filteredFindings := make([]*Finding, len(result.Findings))
	copy(filteredFindings, result.Findings)

	for _, document := range documents {
		packageAdvisories := document.Advisories

		switch advisoryFilterSet {
		case AdvisoriesSetAll:
			filteredFindings = filterFindingsWithAllAdvisories(filteredFindings, packageAdvisories)

		case AdvisoriesSetResolved:
			filteredFindings = filterFindingsWithResolvedAdvisories(filteredFindings, packageAdvisories, result.TargetAPK.Version)

		default:
			return nil, fmt.Errorf("unknown advisory filter set: %s", advisoryFilterSet)
		}
	}

	return filteredFindings, nil
}

func filterFindingsWithAllAdvisories(findings []*Finding, packageAdvisories v2.Advisories) []*Finding {
	return lo.Filter(findings, func(finding *Finding, _ int) bool {
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

func filterFindingsWithResolvedAdvisories(findings []*Finding, packageAdvisories v2.Advisories, currentPackageVersion string) []*Finding {
	return lo.Filter(findings, func(finding *Finding, _ int) bool {
		adv, ok := packageAdvisories.GetByVulnerability(finding.Vulnerability.ID)
		if ok && adv.ResolvedAtVersion(currentPackageVersion) {
			return false
		}

		// Also check any listed aliases
		for _, alias := range finding.Vulnerability.Aliases {
			adv, ok := packageAdvisories.GetByVulnerability(alias)
			if !ok {
				continue
			}

			if adv.ResolvedAtVersion(currentPackageVersion) {
				return false
			}
		}

		return true
	})
}
