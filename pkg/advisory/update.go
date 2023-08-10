package advisory

import (
	"fmt"

	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v1 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v1"
)

// UpdateOptions configures the Update operation.
type UpdateOptions struct {
	// AdvisoryCfgs is the Index of advisory configurations on which to operate.
	AdvisoryCfgs *configs.Index[v1.Document]
}

// Update adds a new entry to an existing advisory (named by the vuln parameter)
// in the configuration at the provided path.
func Update(req Request, opts UpdateOptions) error {
	vulnID := req.Vulnerability
	advisoryEntry := req.toAdvisoryEntry()

	advisoryCfgs := opts.AdvisoryCfgs.Select().WhereName(req.Package)
	if count := advisoryCfgs.Len(); count != 1 {
		return fmt.Errorf("cannot update advisory: found %d advisory documents for package %q", count, req.Package)
	}

	u := v1.NewAdvisoriesSectionUpdater(func(cfg v1.Document) (v1.Advisories, error) {
		advisories := cfg.Advisories
		if _, existsAlready := advisories[vulnID]; !existsAlready {
			return v1.Advisories{}, fmt.Errorf("no advisory exists for %s", vulnID)
		}

		advisories[vulnID] = append(advisories[vulnID], advisoryEntry)

		return advisories, nil
	})
	err := advisoryCfgs.Update(u)
	if err != nil {
		return fmt.Errorf("unable to add entry for advisory %q in %q: %w", vulnID, req.Package, err)
	}

	return nil
}
