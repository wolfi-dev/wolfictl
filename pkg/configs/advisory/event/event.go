package event

import (
	"time"
)

const (
	TypeDetection                  = "detection"
	TypeTruePositiveDetermination  = "true-positive-determination"
	TypeFixed                      = "fixed"
	TypeFalsePositiveDetermination = "false-positive-determination"
)

// Event is a timestamped record of new information regarding the investigation
// and resolution of a potential vulnerability match.
type Event struct {
	// Type is a string that identifies the kind of event. This field is used to
	// determine how to unmarshal the Data field.
	Type string `yaml:"type"`

	// Timestamp is the time at which the event occurred.
	Timestamp time.Time `yaml:"timestamp"`

	// Data is the event-specific data. The type of this field is determined by the
	// Type field.
	Data interface{} `yaml:"data,omitempty"`
}
