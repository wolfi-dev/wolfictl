package v2

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// Timestamp is a time.Time that marshals to and from RFC3339 timestamps.
type Timestamp time.Time

// Now returns the current time as a Timestamp.
func Now() Timestamp {
	return Timestamp(time.Now())
}

const yamlTagTimestamp = "!!timestamp" // see https://yaml.org/type/timestamp.html

// MarshalYAML implements yaml.Marshaler.
func (t Timestamp) MarshalYAML() (interface{}, error) {
	return yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   yamlTagTimestamp,
		Value: t.String(),
	}, nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (t *Timestamp) UnmarshalYAML(v *yaml.Node) error {
	if !(v.Kind == yaml.ScalarNode && v.Tag == yamlTagTimestamp) {
		return fmt.Errorf("expected a timestamp, got %s", v.Tag)
	}

	timeValue, err := time.Parse(time.RFC3339, v.Value)
	if err != nil {
		return fmt.Errorf("unable to parse timestamp: %w", err)
	}

	*t = Timestamp(timeValue)
	return nil
}

// IsZero returns true if the timestamp is the zero value.
func (t Timestamp) IsZero() bool {
	return time.Time(t).IsZero()
}

// Before returns true if t is before u.
func (t Timestamp) Before(u Timestamp) bool {
	return time.Time(t).Before(time.Time(u))
}

// After returns true if t is after u.
func (t Timestamp) After(u Timestamp) bool {
	return time.Time(t).After(time.Time(u))
}

// String returns the timestamp as an RFC3339 string.
func (t Timestamp) String() string {
	return time.Time(t).UTC().Format(time.RFC3339)
}

// Equal returns true if t and u are equal.
func (t Timestamp) Equal(u Timestamp) bool {
	return time.Time(t).Equal(time.Time(u))
}
