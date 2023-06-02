package advisory

import (
	"fmt"
	"strings"

	"chainguard.dev/melange/pkg/build"
	"github.com/hashicorp/go-multierror"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	advisoryconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/advisory"
	"golang.org/x/exp/slices"
)

type ValidateOptions struct {
	// BuildCfgs is the Index of build configurations on which to operate (not used yet).
	BuildCfgs *configs.Index[build.Configuration]

	// AdvisoryCfgs is the Index of advisories on which to operate.
	AdvisoryCfgs *configs.Index[advisoryconfigs.Document]

	// PackageRepositoryURL is the URL to the distro's package repository (e.g. "https://packages.wolfi.dev/os") (not used yet).
	PackageRepositoryURL string

	// The Arches to consider during validation (e.g. "x86_64") (not used yet).
	Arches []string
}

func Validate(opts ValidateOptions) *multierror.Error {
	advCfgs := opts.AdvisoryCfgs.Select().Configurations()

	merr := newMultierror()

	for _, cfg := range advCfgs {
		err := validateAdvisoryDocument(cfg)
		if err != nil {
			merr = multierror.Append(merr, fmt.Errorf(
				"issue(s) found with advisories file for package %q: %w",
				cfg.Package.Name,
				err,
			))
		}
	}

	if merr.Len() > 0 {
		return merr
	}

	return nil
}

func validateAdvisoryDocument(cfg advisoryconfigs.Document) *multierror.Error {
	merr := newMultierror()

	if cfg.Package.Name == "" {
		merr = multierror.Append(
			merr,
			fmt.Errorf("package name must not be empty"),
		)
	}

	if len(cfg.Advisories) == 0 {
		merr = multierror.Append(
			merr,
			fmt.Errorf("this file should not exist if there are no advisories recorded"),
		)
	}

	for advID, advEntries := range cfg.Advisories {
		err := validateAdvisory(advEntries)
		if err != nil {
			merr = multierror.Append(merr, fmt.Errorf(
				"issue(s) found with advisory %q: %w",
				advID,
				err,
			))
		}
	}

	if merr.Len() > 0 {
		return merr
	}

	return nil
}

func validateAdvisory(advEntries []advisoryconfigs.Entry) *multierror.Error {
	merr := newMultierror()

	if len(advEntries) == 0 {
		err := fmt.Errorf("this advisory should not exist if there are no entries recorded")
		if err != nil {
			merr = multierror.Append(merr, err)
		}
	}

	for i, advEntry := range advEntries {
		err := validateAdvisoryEntry(advEntry)
		if err != nil {
			merr = multierror.Append(merr, fmt.Errorf(
				"issue(s) found with event %d (of %d): %w",
				i+1,
				len(advEntries),
				err,
			))
		}
	}

	if merr.Len() > 0 {
		return merr
	}

	return nil
}

func validateAdvisoryEntry(entry advisoryconfigs.Entry) *multierror.Error {
	merr := newMultierror()

	if entry.Timestamp.IsZero() {
		merr = multierror.Append(merr, fmt.Errorf("timestamp must not be zero"))
	}

	if !slices.Contains(vex.Statuses(), string(entry.Status)) {
		err := fmt.Errorf("status is %q but must be one of [%v]", entry.Status, strings.Join(vex.Statuses(), ", "))
		merr = multierror.Append(merr, err)
	}

	err := validateFixedVersion(entry.FixedVersion, entry.Status)
	if err != nil {
		merr = multierror.Append(merr, err)
	}

	err = validateJustification(entry.Justification, entry.Status)
	if err != nil {
		merr = multierror.Append(merr, err)
	}

	err = validateImpactStatement(entry.ImpactStatement, entry.Status)
	if err != nil {
		merr = multierror.Append(merr, err)
	}

	err = validateActionStatement(entry.ActionStatement, entry.Status)
	if err != nil {
		merr = multierror.Append(merr, err)
	}

	if merr.Len() > 0 {
		return merr
	}

	return nil
}

func validateFixedVersion(fixedVersion string, status vex.Status) *multierror.Error {
	merr := newMultierror()

	if status == vex.StatusFixed {
		if fixedVersion == "" {
			merr = multierror.Append(
				merr,
				fmt.Errorf("fixed version must not be empty if status is %q", vex.StatusFixed),
			)
		}
	} else {
		if fixedVersion != "" {
			merr = multierror.Append(
				merr,
				fmt.Errorf("fixed version must be empty if status is not %q", vex.StatusFixed),
			)
		}
	}

	if merr.Len() > 0 {
		return merr
	}

	return nil
}

func validateJustification(justification vex.Justification, status vex.Status) *multierror.Error {
	merr := newMultierror()

	if status == vex.StatusNotAffected {
		if !slices.Contains(vex.Justifications(), string(justification)) {
			merr = multierror.Append(
				merr,
				fmt.Errorf("justification is %q but must be one of [%v] (when status is %q)", justification, strings.Join(vex.Justifications(), ", "), vex.StatusNotAffected),
			)
		}
	} else {
		if justification != "" {
			merr = multierror.Append(
				merr,
				fmt.Errorf("justification must be empty if status is not %q", vex.StatusNotAffected),
			)
		}
	}

	if merr.Len() > 0 {
		return merr
	}

	return nil
}

func validateImpactStatement(impactStatement string, status vex.Status) *multierror.Error {
	merr := newMultierror()

	if status != vex.StatusNotAffected && impactStatement != "" {
		merr = multierror.Append(
			merr,
			fmt.Errorf("impact statement must be empty if status is not %q", vex.StatusNotAffected),
		)
	}

	if merr.Len() > 0 {
		return merr
	}

	return nil
}

func validateActionStatement(actionStatement string, status vex.Status) *multierror.Error {
	merr := newMultierror()

	if status == vex.StatusAffected {
		if actionStatement == "" {
			merr = multierror.Append(
				merr,
				fmt.Errorf("action statement must not be empty if status is %q", vex.StatusAffected),
			)
		}
	} else {
		if actionStatement != "" {
			merr = multierror.Append(
				merr,
				fmt.Errorf("action statement must be empty if status is not %q", vex.StatusAffected),
			)
		}
	}

	if merr.Len() > 0 {
		return merr
	}

	return nil
}

func newMultierror() *multierror.Error {
	merr := new(multierror.Error)
	merr.ErrorFormat = func(errs []error) string {
		var sb strings.Builder

		for _, err := range errs {
			sb.WriteString("\n")
			sb.WriteString(indent(err.Error()))
		}

		return sb.String()
	}
	return merr
}

func indent(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = "  " + line
	}
	return strings.Join(lines, "\n")
}
