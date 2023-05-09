package advisory

import (
	"errors"
	"time"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/wolfi-dev/wolfictl/pkg/configs/advisory"
)

// Request specifies the parameters for creating a new advisory or updating an existing advisory.
type Request struct {
	Package       string
	Vulnerability string
	Status        vex.Status
	Action        string
	Impact        string
	Justification vex.Justification
	FixedVersion  string
	Timestamp     time.Time
}

// Validate returns an error if the Request is invalid.
func (req Request) Validate() error {
	if req.Package == "" {
		return errors.New("package cannot be empty")
	}

	if req.Vulnerability == "" {
		return errors.New("vulnerability cannot be empty")
	}

	if req.Status == "" {
		return errors.New("status cannot be empty")
	}

	switch req.Status {
	case vex.StatusFixed:
		if req.FixedVersion == "" {
			return errors.New("fixed version cannot be empty if status is 'fixed'")
		}
	case vex.StatusAffected:
		if req.Action == "" {
			return errors.New("action cannot be empty if status is 'affected'")
		}
	case vex.StatusNotAffected:
		if req.Justification == "" {
			return errors.New("justification cannot be empty if status is 'not affected'")
		}
	}

	return nil
}

func (req Request) toAdvisoryEntry() advisory.Entry {
	return advisory.Entry{
		Timestamp:       req.Timestamp,
		Status:          req.Status,
		Justification:   req.Justification,
		ImpactStatement: req.Impact,
		ActionStatement: req.Action,
		FixedVersion:    req.FixedVersion,
	}
}
