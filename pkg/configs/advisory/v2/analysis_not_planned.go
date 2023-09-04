package v2

import "errors"

type AnalysisNotPlanned struct {
	// Note should explain why there is no plan to analyze the vulnerability match.
	Note string `yaml:"note"`
}

// Validate returns an error if the AnalysisNotPlanned data is invalid.
func (a AnalysisNotPlanned) Validate() error {
	if a.Note == "" {
		return errors.New("note must not be empty")
	}
	return nil
}
