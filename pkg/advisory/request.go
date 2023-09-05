package advisory

import (
	"errors"

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

	if err := vuln.ValidateID(req.VulnerabilityID); err != nil {
		return err
	}

	if err := errors.Join(lo.Map(req.Aliases, func(alias string, _ int) error {
		return vuln.ValidateID(alias)
	})...); err != nil {
		return err
	}

	if req.VulnerabilityID == "" {
		return errors.New("vulnerability cannot be empty")
	}

	if req.Event.IsZero() {
		return errors.New("event cannot be zero")
	}

	return req.Event.Validate()
}
