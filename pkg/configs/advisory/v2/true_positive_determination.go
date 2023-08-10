package v2

// TruePositiveDetermination is an event that indicates that a previously
// detected vulnerability was acknowledged to be a true positive.
type TruePositiveDetermination struct {
	Note string `yaml:"note,omitempty"`
}
