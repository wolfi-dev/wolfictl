package advisory

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
)

// CreateOptions configures the Create operation.
type CreateOptions struct {
	// AdvisoryDocs is the Index of advisory documents on which to operate.
	AdvisoryDocs *configs.Index[v2.Document]
}

// Create creates a new advisory in the `advisories` section of the document at
// the provided path.
func Create(ctx context.Context, req Request, opts CreateOptions) error {
	err := req.Validate()
	if err != nil {
		return fmt.Errorf("invalid request: %w", err)
	}

	// In addition, validate that the request's AdvisoryID is empty.
	if req.AdvisoryID != "" {
		return fmt.Errorf("advisory ID must be empty for creating a new advisory, got %q", req.AdvisoryID)
	}

	documents := opts.AdvisoryDocs.Select().WhereName(req.Package)
	count := documents.Len()

	switch count {
	case 0:
		// i.e. no advisories file for this package yet
		return createAdvisoryConfig(ctx, opts.AdvisoryDocs, req)

	case 1:
		// i.e. exactly one advisories file for this package
		u := v2.NewAdvisoriesSectionUpdater(func(doc v2.Document) (v2.Advisories, error) {
			for _, alias := range req.Aliases {
				if _, exists := doc.Advisories.GetByVulnerability(alias); exists {
					return v2.Advisories{}, fmt.Errorf("advisory %q already exists for %q", alias, req.Package)
				}
			}

			newAdvisoryID, err := GenerateCGAID()
			if err != nil {
				return v2.Advisories{}, fmt.Errorf("generating CGA ID: %w", err)
			}

			advisories := doc.Advisories
			newAdvisory := v2.Advisory{
				ID:      newAdvisoryID,
				Aliases: req.Aliases,
				Events:  []v2.Event{req.Event},
			}
			advisories = append(advisories, newAdvisory)

			// Ensure the package's advisory list is sorted before returning it.
			sort.Sort(advisories)

			return advisories, nil
		})
		err := documents.Update(ctx, u)
		if err != nil {
			var showIDs string
			if len(req.Aliases) == 1 {
				showIDs = req.Aliases[0]
			} else {
				showIDs = strings.Join(req.Aliases, ", ")
			}
			return fmt.Errorf("unable to create advisory %q for %q: %w", showIDs, req.Package, err)
		}

		// Update the schema version to the latest version.
		err = documents.Update(ctx, v2.NewSchemaVersionSectionUpdater(v2.SchemaVersion))
		if err != nil {
			return fmt.Errorf("unable to update schema version for %q: %w", req.Package, err)
		}

		return nil
	}

	return fmt.Errorf("cannot create advisory: found %d advisory documents for package %q", count, req.Package)
}

func createAdvisoryConfig(ctx context.Context, documents *configs.Index[v2.Document], req Request) error {
	var newAdvisoryID string

	// Continuously generate new CGA IDs until we get a unique one.
	for {
		id, err := GenerateCGAID()
		if err != nil {
			return fmt.Errorf("generating CGA ID: %w", err)
		}

		exists, err := CGAIDExists(ctx, id)
		if err != nil {
			return fmt.Errorf("checking existence of %s: %w", id, err)
		}
		if !exists {
			newAdvisoryID = id
			break
		}
	}

	newAdvisory := v2.Advisory{
		ID:      newAdvisoryID,
		Aliases: req.Aliases,
		Events:  []v2.Event{req.Event},
	}

	err := documents.Create(ctx, fmt.Sprintf("%s.advisories.yaml", req.Package), v2.Document{
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
