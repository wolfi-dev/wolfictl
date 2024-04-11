package v2

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	EventTypeDetection                  = "detection"
	EventTypeTruePositiveDetermination  = "true-positive-determination"
	EventTypeFixed                      = "fixed"
	EventTypeFalsePositiveDetermination = "false-positive-determination"
	EventTypeAnalysisNotPlanned         = "analysis-not-planned"
	EventTypeFixNotPlanned              = "fix-not-planned"
	EventTypePendingUpstreamFix         = "pending-upstream-fix"
)

type EventTypeData interface {
	Detection |
		TruePositiveDetermination |
		Fixed |
		FalsePositiveDetermination |
		AnalysisNotPlanned |
		FixNotPlanned |
		PendingUpstreamFix
}

var (
	// EventTypes is a list of all valid event types.
	EventTypes = []string{
		EventTypeDetection,
		EventTypeTruePositiveDetermination,
		EventTypeFixed,
		EventTypeFalsePositiveDetermination,
		EventTypeAnalysisNotPlanned,
		EventTypeFixNotPlanned,
		EventTypePendingUpstreamFix,
	}
)

// Event is a timestamped record of new information regarding the investigation
// and resolution of a potential vulnerability match.
type Event struct {
	// Timestamp is the time at which the event occurred.
	Timestamp Timestamp `yaml:"timestamp"`

	// Type is a string that identifies the kind of event. This field is used to
	// determine how to unmarshal the Data field.
	Type string `yaml:"type"`

	// Data is the event-specific data. The type of this field is determined by the
	// Type field.
	Data interface{} `yaml:"data,omitempty"`
}

type partialEvent struct {
	Timestamp Timestamp `yaml:"timestamp"`
	Type      string    `yaml:"type"`
	Data      yaml.Node
}

func (e *Event) UnmarshalYAML(v *yaml.Node) error {
	// Unmarshal the event type and timestamp as a "partial event" before unmarshalling the event-type-specific data.
	pe, err := strictUnmarshal[partialEvent](v)
	if err != nil {
		return fmt.Errorf("strict YAML unmarshaling failed: %w", err)
	}
	eventData := *pe

	var event Event

	switch pe.Type {
	case EventTypeDetection:
		event, err = decodeTypedEventData[Detection](eventData)

	case EventTypeTruePositiveDetermination:
		event, err = decodeTypedEventData[TruePositiveDetermination](eventData)

	case EventTypeFixed:
		event, err = decodeTypedEventData[Fixed](eventData)

	case EventTypeFalsePositiveDetermination:
		event, err = decodeTypedEventData[FalsePositiveDetermination](eventData)

	case EventTypeAnalysisNotPlanned:
		event, err = decodeTypedEventData[AnalysisNotPlanned](eventData)

	case EventTypeFixNotPlanned:
		event, err = decodeTypedEventData[FixNotPlanned](eventData)

	case EventTypePendingUpstreamFix:
		event, err = decodeTypedEventData[PendingUpstreamFix](eventData)

	default:
		// TODO: log at warn level: unrecognized event type

		event = Event{
			Timestamp: pe.Timestamp,
			Type:      pe.Type,
		}
	}

	if err != nil {
		return err
	}

	*e = event
	return nil
}

func decodeTypedEventData[T EventTypeData](pe partialEvent) (Event, error) {
	event := Event{
		Timestamp: pe.Timestamp,
		Type:      pe.Type,
	}

	if pe.Data.IsZero() {
		return event, nil
	}

	data, err := strictUnmarshal[T](&pe.Data)
	if err != nil {
		return Event{}, fmt.Errorf("strict YAML unmarshaling failed: %w", err)
	}

	event.Data = *data

	return event, nil
}

func (e Event) Validate() error {
	return errors.Join(
		e.validateTimestamp(),
		e.validateType(),
		e.validateData(),
	)
}

func (e Event) validateTimestamp() error {
	if e.Timestamp.IsZero() {
		return fmt.Errorf("timestamp must not be zero")
	}

	futureCutoff := time.Now().Add(2 * time.Hour)
	if e.Timestamp.After(Timestamp(futureCutoff)) {
		return fmt.Errorf("timestamp must not be in the future")
	}

	return nil
}

func (e Event) validateType() error {
	if e.Type == "" {
		return fmt.Errorf("type must not be empty")
	}

	if !slices.Contains(EventTypes, e.Type) {
		return fmt.Errorf("type is %q but must be one of [%v]", e.Type, strings.Join(EventTypes, ", "))
	}

	return nil
}

func (e Event) validateData() error {
	switch e.Type {
	case EventTypeDetection:
		return validateTypedEventData[Detection](e.Data)

	case EventTypeTruePositiveDetermination:
		// no validation needed currently

	case EventTypeFixed:
		return validateTypedEventData[Fixed](e.Data)

	case EventTypeFalsePositiveDetermination:
		return validateTypedEventData[FalsePositiveDetermination](e.Data)

	case EventTypeAnalysisNotPlanned:
		return validateTypedEventData[AnalysisNotPlanned](e.Data)

	case EventTypeFixNotPlanned:
		return validateTypedEventData[FixNotPlanned](e.Data)

	case EventTypePendingUpstreamFix:
		return validateTypedEventData[PendingUpstreamFix](e.Data)
	}

	return nil
}

func (e Event) IsZero() bool {
	return e.Timestamp.IsZero() && e.Type == "" && e.Data == nil
}

func validateTypedEventData[T interface{ Validate() error }](data interface{}) error {
	d, ok := data.(T)
	if !ok {
		return fmt.Errorf("data must be of type %T", new(T))
	}

	return d.Validate()
}
