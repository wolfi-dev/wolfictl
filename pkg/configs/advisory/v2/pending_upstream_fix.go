package v2

import "errors"

// PendingUpstreamFix is an event type that indicates that the package is
// expected to remain unfixed until the maintainers of the package's upstream
// project implement a fix themselves.
//
// This event type is distinct from FixNotPlanned, which signals an expectation
// that no fix is ever coming.
//
// PendingUpstreamFix is used in cases where a fix requires nontrivial upstream
// changes that should be managed by the upstream maintainers.
type PendingUpstreamFix struct {
	// Note should explain why an upstream fix is anticipated or necessary.
	Note string `yaml:"note"`
}

// Validate returns an error if the PendingUpstreamFix data is invalid.
func (f PendingUpstreamFix) Validate() error {
	if f.Note == "" {
		return errors.New("note must not be empty")
	}
	return nil
}
