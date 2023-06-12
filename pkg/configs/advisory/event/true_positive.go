package event

// TruePositiveDetermination is an event that indicates that a previously
// detected vulnerability was acknowledged to be a true positive.
type TruePositiveDetermination struct {
	Notes string `yaml:"notes,omitempty"`
}
