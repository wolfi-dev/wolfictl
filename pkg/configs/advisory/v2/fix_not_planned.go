package v2

import "errors"

// FixNotPlanned is an event type that indicates that the package is expected
// not to receive a fix for the vulnerability.
type FixNotPlanned struct {
	// Note should explain why there is no plan to fix the vulnerability.
	Note string `yaml:"note"`
}

// Validate returns an error if the FixNotPlanned data is invalid.
func (f FixNotPlanned) Validate() error {
	if f.Note == "" {
		return errors.New("note must not be empty")
	}
	return nil
}
