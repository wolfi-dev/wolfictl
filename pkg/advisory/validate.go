package advisory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"chainguard.dev/melange/pkg/config"
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

	// SelectedPackages is the set of packages to operate on. If empty, all packages
	// will be operated on.
	SelectedPackages map[string]struct{}

	// Now is the time to use as the current time for recency validation.
	Now time.Time

	// AliasFinder is the alias finder to use for discovering aliases for the given
	// vulnerabilities.
	AliasFinder AliasFinder

	// PackageConfigurations is the index of distro package configurations to use
	// for validating the advisories.
	PackageConfigurations *configs.Index[config.Configuration]
}

func Validate(ctx context.Context, opts ValidateOptions) error {
	var errs []error

	documentErrs := lo.Map(
		opts.AdvisoryDocs.Select().Configurations(),
		func(doc v2.Document, _ int) error {
			if len(opts.SelectedPackages) > 0 {
				if _, ok := opts.SelectedPackages[doc.Name()]; !ok {
					// Skip this document, since it's not in the set of selected packages.
					return nil
				}
			}

			return doc.Validate()
		},
	)
	errs = append(errs, errorhelpers.LabelError("basic validation failure(s)", errors.Join(documentErrs...)))

	if opts.BaseAdvisoryDocs != nil {
		diff := IndexDiff(opts.BaseAdvisoryDocs, opts.AdvisoryDocs)
		errs = append(errs, opts.validateIndexDiff(diff))
	}

	if opts.PackageConfigurations != nil {
		errs = append(errs, opts.validatePackageExistence())
	}

	if opts.AliasFinder != nil {
		errs = append(errs, opts.validateAliasSetCompleteness(ctx))
	}

	return errors.Join(errs...)
}

func (opts ValidateOptions) validatePackageExistence() error {
	var errs []error

	documents := opts.AdvisoryDocs.Select().Configurations()
	for i := range documents {
		doc := documents[i]

		if len(opts.SelectedPackages) > 0 {
			if _, ok := opts.SelectedPackages[doc.Name()]; !ok {
				// Skip this document, since it's not in the set of selected packages.
				continue
			}
		}

		if opts.PackageConfigurations.Select().WhereName(doc.Name()).Len() == 0 {
			errs = append(errs, errorhelpers.LabelError(doc.Name(), errors.New("this package is not defined in any distro package configuration")))
		}
	}

	return errorhelpers.LabelError("package existence validation failure(s)", errors.Join(errs...))
}

func (opts ValidateOptions) validateAliasSetCompleteness(ctx context.Context) error {
	var errs []error

	documents := opts.AdvisoryDocs.Select().Configurations()
	for i := range documents {
		doc := documents[i]

		if len(opts.SelectedPackages) > 0 {
			if _, ok := opts.SelectedPackages[doc.Name()]; !ok {
				// Skip this document, since it's not in the set of selected packages.
				continue
			}
		}

		var docErrs []error

		for i := range doc.Advisories {
			adv := doc.Advisories[i]
			var advErrs []error

			switch {
			case strings.HasPrefix(adv.ID, "CVE-"):
				ghsas, err := opts.AliasFinder.GHSAsForCVE(ctx, adv.ID)
				if err != nil {
					return fmt.Errorf("failed to query GHSA aliases for CVE %q: %w", adv.ID, err)
				}
				for _, ghsa := range ghsas {
					if !slices.Contains(adv.Aliases, ghsa) {
						advErrs = append(advErrs, fmt.Errorf("missing GHSA alias %q from set [%s]", ghsa, strings.Join(adv.Aliases, ", ")))
					}
				}

			case strings.HasPrefix(adv.ID, "GHSA-"):
				cve, err := opts.AliasFinder.CVEForGHSA(ctx, adv.ID)
				if err != nil {
					return fmt.Errorf("failed to query CVE alias for GHSA %q: %w", adv.ID, err)
				}
				if cve != "" {
					advErrs = append(advErrs, fmt.Errorf("%q should be listed as an alias, and %q should be the advisory ID", adv.ID, cve))
				}
			}

			docErrs = append(docErrs, errorhelpers.LabelError(adv.ID, errors.Join(advErrs...)))
		}

		errs = append(errs, errorhelpers.LabelError(doc.Name(), errors.Join(docErrs...)))
	}

	return errorhelpers.LabelError("alias set completeness validation failure(s)", errors.Join(errs...))
}

func (opts ValidateOptions) validateIndexDiff(diff IndexDiffResult) error {
	var errs []error

	docRemovedErrs := lo.Map(diff.Removed, func(doc v2.Document, _ int) error {
		if len(opts.SelectedPackages) > 0 {
			if _, ok := opts.SelectedPackages[doc.Name()]; !ok {
				// Skip this document, since it's not in the set of selected packages.
				return nil
			}
		}

		return errorhelpers.LabelError(doc.Name(), errors.New("document was removed"))
	})
	errs = append(errs, docRemovedErrs...)

	for _, documentAdvisories := range diff.Modified {
		if len(opts.SelectedPackages) > 0 {
			if _, ok := opts.SelectedPackages[documentAdvisories.Name]; !ok {
				// Skip this document, since it's not in the set of selected packages.
				continue
			}
		}

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

			for i, event := range adv.AddedEvents {
				advErrs = append(advErrs, errorhelpers.LabelError(fmt.Sprintf("event %d (just added)", i+1), opts.validateRecency(event)))
			}

			docErrs = append(
				docErrs,
				errorhelpers.LabelError(
					adv.ID,
					errors.Join(advErrs...),
				),
			)
		}

		for i := range documentAdvisories.Added {
			adv := documentAdvisories.Added[i]

			var advErrs []error
			for i, event := range adv.Events {
				advErrs = append(advErrs, errorhelpers.LabelError(fmt.Sprintf("event %d (just added)", i+1), opts.validateRecency(event)))
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

	for i := range diff.Added {
		doc := diff.Added[i]

		if len(opts.SelectedPackages) > 0 {
			if _, ok := opts.SelectedPackages[doc.Name()]; !ok {
				// Skip this document, since it's not in the set of selected packages.
				continue
			}
		}

		var docErrs []error
		for advIndex := range doc.Advisories {
			adv := doc.Advisories[advIndex]

			var advErrs []error
			for i, event := range adv.Events {
				advErrs = append(advErrs, errorhelpers.LabelError(fmt.Sprintf("event %d (just added)", i+1), opts.validateRecency(event)))
			}
			docErrs = append(
				docErrs,
				errorhelpers.LabelError(
					adv.ID,
					errors.Join(advErrs...),
				),
			)
		}

		errs = append(errs, errorhelpers.LabelError(doc.Name(), errors.Join(docErrs...)))
	}

	return errorhelpers.LabelError("invalid change(s) in diff", errors.Join(errs...))
}

const eventMaxValidAgeInDays = 3

func (opts ValidateOptions) isRecent(t time.Time) bool {
	const maxAge = eventMaxValidAgeInDays * 24 * time.Hour // 3 days
	return opts.Now.Sub(t) < maxAge
}

func (opts ValidateOptions) validateRecency(event v2.Event) error {
	if !opts.isRecent(time.Time(event.Timestamp)) {
		return fmt.Errorf(
			"event's timestamp (%s) set to more than %d days ago; timestamps should accurately capture event creation time",
			event.Timestamp,
			eventMaxValidAgeInDays,
		)
	}
	return nil
}
