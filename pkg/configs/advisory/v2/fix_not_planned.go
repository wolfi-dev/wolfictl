package v2

import "errors"

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
