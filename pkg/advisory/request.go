package advisory

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/chainguard-dev/clog"
	"github.com/samber/lo"

	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/vuln"
)

// Request specifies the parameters for creating a new advisory or updating an existing advisory.
type Request struct {
	// Package is the name of the distro package for which the advisory is being
	// created.
	Package string

	// AdvisoryID is the ID for the advisory being updated. If this Request is for
	// creating a new advisory, this should be empty. If a value is provided, it
	// should be of the form "CGA-xxxx-xxxx-xxxx".
	AdvisoryID string

	// Aliases is a list of vulnerability IDs that are known aliases for the
	// advisory.
	Aliases []string

	// Event is the event to add to the advisory.
	Event v2.Event
}

// VulnerabilityIDs returns the list of vulnerability IDs for the Request. This
// is a combination of the Aliases and the AdvisoryID.
func (req Request) VulnerabilityIDs() []string {
	ids := slices.Clone(req.Aliases)

	if req.AdvisoryID != "" {
		ids = append(ids, req.AdvisoryID)
	}

	return slices.Compact(ids)
}

var (
	// ErrEmptyPackage is returned when the Package field is empty.
	ErrEmptyPackage = errors.New("package cannot be empty")

	// ErrInvalidAdvisoryID is returned when the AdvisoryID field value is not a
	// valid CGA ID.
	ErrInvalidAdvisoryID = errors.New("advisory ID must be a valid CGA ID when provided")

	// ErrInvalidVulnerabilityID is returned when an alias is not a valid vulnerability ID.
	ErrInvalidVulnerabilityID = errors.New("alias must be a valid vulnerability ID")

	// ErrCGAIDAsAlias is returned when a CGA ID is used as an alias.
	ErrCGAIDAsAlias = errors.New("CGA ID cannot be used as an alias")

	// ErrZeroEvent is returned when the Event field is zero.
	ErrZeroEvent = errors.New("event cannot be zero")
)

// Validate returns an error if the Request is invalid.
func (req Request) Validate() error {
	var errs []error

	if req.Package == "" {
		errs = append(errs, ErrEmptyPackage)
	}

	if err := errors.Join(lo.Map(req.Aliases, func(alias string, _ int) error {
		if vuln.RegexCGA.MatchString(alias) {
			return ErrCGAIDAsAlias
		}

		if err := vuln.ValidateID(alias); err != nil {
			return fmt.Errorf("%q: %w", alias, ErrInvalidVulnerabilityID)
		}
		return nil
	})...); err != nil {
		errs = append(errs, err)
	}

	if req.AdvisoryID != "" && !vuln.RegexCGA.MatchString(req.AdvisoryID) {
		errs = append(errs, ErrInvalidAdvisoryID)
	}

	if req.Event.IsZero() {
		errs = append(errs, ErrZeroEvent)
	}

	errs = append(errs, req.Event.Validate())

	return errors.Join(errs...)
}

// ResolveAliases ensures that any CVE IDs and GHSA IDs for the request's
// vulnerability are discovered and stored as Aliases, based on the initial set
// of known aliases.
func (req Request) ResolveAliases(ctx context.Context, af AliasFinder) (*Request, error) {
	logger := clog.FromContext(ctx)

	var newAliases []string

	for _, alias := range req.Aliases {
		switch {
		case vuln.RegexGHSA.MatchString(alias):
			cve, err := af.CVEForGHSA(ctx, alias)
			if err != nil {
				return nil, fmt.Errorf("resolving GHSA %q: %w", alias, err)
			}

			newAliases = append(newAliases, cve)
			continue

		case vuln.RegexCVE.MatchString(alias):
			ghsas, err := af.GHSAsForCVE(ctx, alias)
			if err != nil {
				return nil, fmt.Errorf("resolving CVE %q: %w", alias, err)
			}

			newAliases = append(newAliases, ghsas...)
			continue

		default:
			logger.Warnf("not resolving aliases for unknown vulnerability ID format: %q", alias)
		}
	}

	req.Aliases = append(req.Aliases, newAliases...)
	slices.Sort(req.Aliases)
	req.Aliases = slices.Compact(req.Aliases)

	return &req, nil
}
