package advisory

import (
	"fmt"

	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
)

// CreateOptions configures the Create operation.
type CreateOptions struct {
	// AdvisoryCfgs is the Index of advisory configurations on which to operate.
	AdvisoryCfgs *configs.Index[v2.Document]
}

// Create creates a new advisory in the `advisories` section of the configuration
// at the provided path.
func Create(req Request, opts CreateOptions) error {
	err := req.Validate()
	if err != nil {
		return err
	}

	advisoryCfgs := opts.AdvisoryCfgs.Select().WhereName(req.Package)
	count := advisoryCfgs.Len()

	switch count {
	case 0:
		// i.e. no advisories file for this package yet
		return createAdvisoryConfig(opts.AdvisoryCfgs, req)

	case 1:
		newAdvisoryID := req.VulnerabilityID

		// i.e. exactly one advisories file for this package
		u := v2.NewAdvisoriesSectionUpdater(func(doc v2.Document) (v2.Advisories, error) {
			if doc.Advisories.Contains(newAdvisoryID) {
				return v2.Advisories{}, fmt.Errorf("advisory %q already exists for %q", newAdvisoryID, req.Package)
			}

			advs := doc.Advisories
			newAdvisory := v2.Advisory{
				ID:      newAdvisoryID,
				Aliases: req.Aliases,
				Events:  []v2.Event{req.Event},
			}
			advs = append(advs, newAdvisory)

			return advs, nil
		})
		err := advisoryCfgs.Update(u)
		if err != nil {
			return fmt.Errorf("unable to create advisory %q for %q: %w", newAdvisoryID, req.Package, err)
		}

		return nil
	}

	return fmt.Errorf("cannot create advisory: found %d advisory documents for package %q", count, req.Package)
}

func createAdvisoryConfig(documents *configs.Index[v2.Document], req Request) error {
	newAdvisoryID := req.VulnerabilityID
	newAdvisory := v2.Advisory{
		ID:      newAdvisoryID,
		Aliases: req.Aliases,
		Events:  []v2.Event{req.Event},
	}

	err := documents.Create(fmt.Sprintf("%s.advisories.yaml", req.Package), v2.Document{
		SchemaVersion: v2.SchemaVersion,
		Package: v2.Package{
			Name: req.Package,
		},
		Advisories: v2.Advisories{newAdvisory},
	})
	if err != nil {
		return err
	}

	return nil
}
