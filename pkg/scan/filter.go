package scan

import (
	"fmt"

	"github.com/samber/lo"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	advisoryconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/advisory"
)

const (
	AdvisoriesSetResolved = "resolved"
	AdvisoriesSetAll      = "all"
)

var ValidAdvisoriesSets = []string{AdvisoriesSetResolved, AdvisoriesSetAll}

// FilterWithAdvisories filters the findings in the result based on the advisories for the target APK.
func FilterWithAdvisories(result *Result, advisoryCfgs *configs.Index[advisoryconfigs.Document], advisoryFilterSet string) ([]*Finding, error) {
	if result == nil {
		return nil, fmt.Errorf("result cannot be nil")
	}

	if advisoryCfgs == nil {
		return nil, fmt.Errorf("advisory configs cannot be nil")
	}

	documents := advisoryCfgs.Select().WhereName(result.TargetAPK.Name).Configurations()
	if len(documents) == 0 {
		// No advisory configs for this package, so we know we wouldn't be able to filter anything.
		return result.Findings, nil
	}

	// We know there's an advisories document for this package, so we can get the advisories.
	packageAdvisories := documents[0].Advisories

	switch advisoryFilterSet {
	case AdvisoriesSetAll:
		resultFindings := lo.Filter(result.Findings, func(finding *Finding, _ int) bool {
			adv := packageAdvisories[finding.Vulnerability.ID]

			// If the advisory contains any entries, filter it out!
			if len(adv) >= 1 {
				return false
			}

			// Also check any listed aliases
			for _, alias := range finding.Vulnerability.Aliases {
				adv := packageAdvisories[alias]
				if len(adv) >= 1 {
					return false
				}
			}

			return true
		})

		return resultFindings, nil

	case AdvisoriesSetResolved:
		resultFindings := lo.Filter(result.Findings, func(finding *Finding, _ int) bool {
			adv := packageAdvisories[finding.Vulnerability.ID]

			if advisory.IsResolved(adv, result.TargetAPK.Version) {
				return false
			}

			// Also check any listed aliases
			for _, alias := range finding.Vulnerability.Aliases {
				adv := packageAdvisories[alias]

				if advisory.IsResolved(adv, result.TargetAPK.Version) {
					return false
				}
			}

			return true
		})

		return resultFindings, nil
	}

	return nil, fmt.Errorf("unknown advisory filter set: %s", advisoryFilterSet)
}
