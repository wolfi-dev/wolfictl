package v2

import "errors"

// AnalysisNotPlanned is an event type that indicates that the vulnerability's
// match to the package that this advisory refers to is not expected to be
// analyzed further by the distro maintainers.
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
