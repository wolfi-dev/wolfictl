package advisory

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
)

// UpdateOptions configures the Update operation.
type UpdateOptions struct {
	// AdvisoryDocs is the Index of advisory documents on which to operate.
	AdvisoryDocs *configs.Index[v2.Document]
}

// Update adds a new event to an existing advisory in the document at the
// provided path. If the request's AdvisoryID is set, the advisory with that ID
// is updated. Otherwise, the first advisory found for the package with the one
// of the provided aliases is updated.
func Update(ctx context.Context, req Request, opts UpdateOptions) error {
	err := req.Validate()
	if err != nil {
		return fmt.Errorf("invalid request: %w", err)
	}

	documents := opts.AdvisoryDocs.Select().WhereName(req.Package)
	if count := documents.Len(); count != 1 {
		return fmt.Errorf("cannot update advisory: found %d advisory documents for package %q", count, req.Package)
	}

	u := v2.NewAdvisoriesSectionUpdater(func(doc v2.Document) (v2.Advisories, error) {
		advisories := doc.Advisories

		// If the request specifies the advisory ID, that takes priority. Otherwise, use
		// the aliases to find the advisory.

		var adv v2.Advisory
		var ok bool
		if req.AdvisoryID != "" {
			// Exact match on advisory ID!

			adv, ok = advisories.Get(req.AdvisoryID)
			if !ok {
				return nil, fmt.Errorf("advisory %q does not exist", req.AdvisoryID)
			}
		} else {
			// Try to find the advisory by its aliases.

			adv, ok = advisories.GetByAnyVulnerability(req.Aliases...)
			if !ok {
				return nil, fmt.Errorf("advisory with alias(es) %q does not exist", strings.Join(req.Aliases, ", "))
			}
		}

		adv = adv.MergeInAliases(req.Aliases...)
		adv.Events = append(adv.Events, req.Event)

		advisories = advisories.Update(adv.ID, adv)

		// Ensure the package's advisory list is sorted before returning it.
		sort.Sort(advisories)

		return advisories, nil
	})
	err = documents.Update(ctx, u)
	if err != nil {
		return fmt.Errorf("unable to add entry for advisory %q in %q: %w", req.Aliases[0], req.Package, err)
	}

	// Update the schema version to the latest version.
	err = documents.Update(ctx, v2.NewSchemaVersionSectionUpdater(v2.SchemaVersion))
	if err != nil {
		return fmt.Errorf("unable to update schema version for %q: %w", req.Package, err)
	}

	return nil
}
