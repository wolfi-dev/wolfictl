package advisory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/samber/lo"

	cgaid "github.com/chainguard-dev/advisory-schema/pkg/advisory"
	v2 "github.com/chainguard-dev/advisory-schema/pkg/advisory/v2"
	vulnadvs "github.com/chainguard-dev/advisory-schema/pkg/vuln"
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
		if cgaid.RegexCGA.MatchString(alias) {
			return ErrCGAIDAsAlias
		}

		if err := vulnadvs.ValidateID(alias); err != nil {
			return fmt.Errorf("%q: %w", alias, ErrInvalidVulnerabilityID)
		}
		return nil
	})...); err != nil {
		errs = append(errs, err)
	}

	if req.AdvisoryID != "" && !cgaid.RegexCGA.MatchString(req.AdvisoryID) {
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
		case vulnadvs.RegexGHSA.MatchString(alias):
			cve, err := af.CVEForGHSA(ctx, alias)
			if err != nil {
				return nil, fmt.Errorf("resolving GHSA %q: %w", alias, err)
			}

			newAliases = append(newAliases, cve)
			continue

		case vulnadvs.RegexCVE.MatchString(alias):
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

// RequestParams is a flattened, utility data structure that can be used to
// generate one or more Requests.
type RequestParams struct {
	PackageNames, Vulns []string

	Timestamp, EventType, FixedVersion, FalsePositiveType, FalsePositiveNote, TruePositiveNote, Note string
}

const (
	RequestParamPackageNames      = "PackageNames"
	RequestParamVulns             = "Vulns"
	RequestParamTimestamp         = "Timestamp"
	RequestParamEventType         = "EventType"
	RequestParamFixedVersion      = "FixedVersion"
	RequestParamFalsePositiveType = "FalsePositiveType"
	RequestParamFalsePositiveNote = "FalsePositiveNote"
	RequestParamTruePositiveNote  = "TruePositiveNote"
	RequestParamNote              = "Note"
)

// MissingValues returns a slice of names of fields that are missing, such that
// generating any Request data is not possible. If enough fields are present to
// potentially generate a Request, an empty slice is returned. This method does
// not validate the values themselves.
func (p RequestParams) MissingValues() []string {
	var missing []string

	if len(p.PackageNames) == 0 {
		missing = append(missing, RequestParamPackageNames)
	}

	if len(p.Vulns) == 0 {
		missing = append(missing, RequestParamVulns)
	}

	if p.EventType == "" {
		missing = append(missing, RequestParamEventType)
	}

	if p.Timestamp == "" {
		missing = append(missing, RequestParamTimestamp)
	}

	if p.EventType == v2.EventTypeFixed && p.FixedVersion == "" {
		missing = append(missing, RequestParamFixedVersion)
	}

	if p.EventType == v2.EventTypeFalsePositiveDetermination {
		if p.FalsePositiveType == "" {
			missing = append(missing, RequestParamFalsePositiveType)
		}

		if p.FalsePositiveNote == "" && p.Note == "" {
			missing = append(missing, RequestParamFalsePositiveNote)
		}
	}

	if p.EventType == v2.EventTypeTruePositiveDetermination && p.TruePositiveNote == "" && p.Note == "" {
		missing = append(missing, RequestParamTruePositiveNote)
	}

	if p.EventType == v2.EventTypeAnalysisNotPlanned && p.Note == "" {
		missing = append(missing, RequestParamNote)
	}

	if p.EventType == v2.EventTypeFixNotPlanned && p.Note == "" {
		missing = append(missing, RequestParamNote)
	}

	if p.EventType == v2.EventTypePendingUpstreamFix && p.Note == "" {
		missing = append(missing, RequestParamNote)
	}

	return missing
}

// GenerateRequests returns a slice of new Requests generated using the data
// provided in the RequestParams.
func (p *RequestParams) GenerateRequests() ([]Request, error) {
	if m := p.MissingValues(); len(m) > 0 {
		return nil, fmt.Errorf("missing values: %v", m)
	}

	timestamp, err := resolveTimestamp(p.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("resolving timestamp: %w", err)
	}

	reqs := make([]Request, 0, len(p.PackageNames)*len(p.Vulns))

	// For now, introduce p.note as a fallback value for event-specific notes. Then
	// in the future, we could deprecate and remove the event-specific note flags.

	event := v2.Event{
		Timestamp: timestamp,
		Type:      p.EventType,
		Data:      nil,
	}

	switch event.Type {
	case v2.EventTypeFixed:
		event.Data = v2.Fixed{
			FixedVersion: p.FixedVersion,
		}

	case v2.EventTypeFalsePositiveDetermination:
		note := p.FalsePositiveNote
		if note == "" {
			note = p.Note
		}
		event.Data = v2.FalsePositiveDetermination{
			Type: p.FalsePositiveType,
			Note: note,
		}

	case v2.EventTypeTruePositiveDetermination:
		note := p.TruePositiveNote
		if note == "" {
			note = p.Note
		}
		event.Data = v2.TruePositiveDetermination{
			Note: note,
		}

	case v2.EventTypeAnalysisNotPlanned:
		event.Data = v2.AnalysisNotPlanned{
			Note: p.Note,
		}

	case v2.EventTypeFixNotPlanned:
		event.Data = v2.FixNotPlanned{
			Note: p.Note,
		}

	case v2.EventTypePendingUpstreamFix:
		event.Data = v2.PendingUpstreamFix{
			Note: p.Note,
		}
	}

	for _, packageName := range p.PackageNames {
		for _, id := range p.Vulns {
			cgaID := ""
			var aliases []string

			// If the vuln is a CGA ID, use it as the AdvisoryID and set the aliases to the
			// empty slice. Otherwise, use the ID as an alias. The RequestParams type cannot
			// be used to generate a Request that has both an AdvisoryID and an alias at the
			// same time.

			if cgaid.RegexCGA.MatchString(id) {
				cgaID = id
			} else {
				aliases = []string{id}
			}

			r := Request{
				Package:    packageName,
				AdvisoryID: cgaID,
				Aliases:    aliases,
				Event:      event,
			}

			reqs = append(reqs, r)
		}
	}

	return reqs, nil
}

func resolveTimestamp(ts string) (v2.Timestamp, error) {
	if ts == "now" {
		return v2.Now(), nil
	}

	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return v2.Timestamp{}, fmt.Errorf("unable to parse timestamp: %w", err)
	}

	return v2.Timestamp(t), nil
}

// MatchToRequest takes an input slice of PackageAdvisory and a Request and
// returns the first PackageAdvisory that matches the Request. If no match is
// found, it returns nil.
//
// A "match" is defined as meeting all the following criteria: having the same
// Package name; if the Request's AdvisoryID is set, it must match the
// PackageAdvisory's ID; and if the Request has Aliases and no AdvisoryID, at
// least one of the Aliases must match the PackageAdvisory's Aliases.
func MatchToRequest(advs []v2.PackageAdvisory, req Request) *v2.PackageAdvisory {
	for _, adv := range advs {
		if adv.PackageName != req.Package {
			continue
		}

		if req.AdvisoryID != "" && adv.ID != req.AdvisoryID {
			continue
		}

		if len(req.Aliases) > 0 && req.AdvisoryID == "" {
			for _, reqAlias := range req.Aliases {
				if adv.DescribesVulnerability(reqAlias) {
					return &adv
				}
			}

			continue
		}

		return &adv
	}

	return nil
}
