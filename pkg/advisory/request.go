package advisory

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/samber/lo"

	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/vuln"
)

// Request specifies the parameters for creating a new advisory or updating an existing advisory.
type Request struct {
	Package         string
	VulnerabilityID string
	Aliases         []string
	Event           v2.Event
}

// Validate returns an error if the Request is invalid.
func (req Request) Validate() error {
	if req.Package == "" {
		return errors.New("package cannot be empty")
	}

	if len(req.Aliases) == 0 {
		return errors.New("aliases should have at least one vulnerability ID")
	}

	if err := errors.Join(lo.Map(req.Aliases, func(alias string, _ int) error {
		return vuln.ValidateID(alias)
	})...); err != nil {
		return err
	}

	if req.VulnerabilityID != "" {
		return errors.New("vulnerability should be empty")
	}

	if req.Event.IsZero() {
		return errors.New("event cannot be zero")
	}

	return req.Event.Validate()
}

// ResolveAliases ensures that the request ID is a CVE and that any known GHSA
// IDs are discovered and stored as Aliases.
func (req Request) ResolveAliases(ctx context.Context, af AliasFinder) (*Request, error) {
	switch {
	case vuln.RegexGHSA.MatchString(req.VulnerabilityID):
		cve, err := af.CVEForGHSA(ctx, req.VulnerabilityID)
		if err != nil {
			return nil, fmt.Errorf("resolving GHSA %q: %w", req.VulnerabilityID, err)
		}

		req.Aliases = append(req.Aliases, req.VulnerabilityID)
		slices.Sort(req.Aliases)
		req.Aliases = slices.Compact(req.Aliases)

		req.VulnerabilityID = cve
		return &req, nil

	case vuln.RegexCVE.MatchString(req.VulnerabilityID):
		ghsas, err := af.GHSAsForCVE(ctx, req.VulnerabilityID)
		if err != nil {
			return nil, fmt.Errorf("resolving CVE %q: %w", req.VulnerabilityID, err)
		}

		req.Aliases = append(req.Aliases, ghsas...)
		slices.Sort(req.Aliases)
		req.Aliases = slices.Compact(req.Aliases)

		return &req, nil
	}

	return nil, fmt.Errorf("unsupported vulnerability ID format: %q", req.VulnerabilityID)
}
