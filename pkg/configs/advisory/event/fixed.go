package event

import "time"

// Fixed is an event that indicates that a vulnerability has been remediated in
// an updated version of the distribution package.
type Fixed struct {
	// FixedVersion is the version of the distribution package that contains
	// the fix to the vulnerability.
	FixedVersion string `yaml:"fixed-version"`
}

func NewFixed(timestamp time.Time, event Fixed) Event {
	return Event{
		Type:      TypeFixed,
		Timestamp: timestamp,
		Data:      event,
	}
}
