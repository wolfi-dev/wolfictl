package event

import "time"

// Fixed is an event that indicates that a vulnerability has been fixed.
type Fixed struct {
	FixedPackageVersion string `yaml:"fixed-package-version"`
}

func NewFixed(timestamp time.Time, event Fixed) Event {
	return Event{
		Type:      TypeFixed,
		Timestamp: timestamp,
		Data:      event,
	}
}
