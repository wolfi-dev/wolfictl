package advisory

import (
	"errors"

	"github.com/wolfi-dev/wolfictl/pkg/configs/advisory/event"
)

// Request specifies the parameters for creating a new advisory or updating an existing advisory.
type Request struct {
	Package       string
	Vulnerability string
	Event         event.Event
}

// Validate returns an error if the Request is invalid.
func (req Request) Validate() error {
	if req.Package == "" {
		return errors.New("package cannot be empty")
	}

	if req.Vulnerability == "" {
		return errors.New("vulnerability cannot be empty")
	}

	// TODO: validate event

	return nil
}
