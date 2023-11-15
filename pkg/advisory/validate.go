package advisory

import (
	"errors"
	"fmt"

	"github.com/samber/lo"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/internal/errorhelpers"
)

type ValidateOptions struct {
	// AdvisoryDocs is the Index of advisories on which to operate.
	AdvisoryDocs *configs.Index[v2.Document]

	// BaseAdvisoryDocs is the Index of advisories used as a comparison basis to
	// understand what is changing in AdvisoryDocs. If nil, no comparison-based
	// validation will be performed.
	BaseAdvisoryDocs *configs.Index[v2.Document]
}

func Validate(opts ValidateOptions) error {
	var errs []error

	documentErrs := lo.Map(
		opts.AdvisoryDocs.Select().Configurations(),
		func(doc v2.Document, _ int) error {
			return doc.Validate()
		},
	)
	errs = append(errs, errorhelpers.LabelError("basic validation failure(s)", errors.Join(documentErrs...)))

	if opts.BaseAdvisoryDocs != nil {
		diff := IndexDiff(opts.BaseAdvisoryDocs, opts.AdvisoryDocs)
		errs = append(errs, validateIndexDiff(diff))
	}

	return errors.Join(errs...)
}

func validateIndexDiff(diff IndexDiffResult) error {
	var errs []error

	docRemovedErrs := lo.Map(diff.Removed, func(doc v2.Document, _ int) error {
		return errorhelpers.LabelError(doc.Name(), errors.New("document was removed"))
	})
	errs = append(errs, docRemovedErrs...)

	for _, documentAdvisories := range diff.Modified {
		var docErrs []error

		advsRemovedErrs := lo.Map(documentAdvisories.Removed, func(adv v2.Advisory, _ int) error {
			return errorhelpers.LabelError(adv.ID, errors.New("advisory was removed"))
		})
		docErrs = append(docErrs, advsRemovedErrs...)

		for i := range documentAdvisories.Modified {
			adv := documentAdvisories.Modified[i]

			var advErrs []error
			if len(adv.RemovedEvents) > 0 {
				if len(adv.AddedEvents) > 0 {
					// If both removed and added events are non-zero, then it's not easy to
					// differentiate whether events were modified, or removed and added.
					advErrs = append(advErrs, fmt.Errorf("one or more events were modified or removed"))
				} else {
					advErrs = append(advErrs, errors.New("one or more events were removed"))
				}
			}
			docErrs = append(
				docErrs,
				errorhelpers.LabelError(
					adv.ID,
					errors.Join(advErrs...),
				),
			)
		}
		errs = append(errs, errorhelpers.LabelError(documentAdvisories.Name, errors.Join(docErrs...)))
	}

	return errorhelpers.LabelError("invalid change(s) in diff", errors.Join(errs...))
}
