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
)

type EventTypeData interface {
	Detection | TruePositiveDetermination | Fixed | FalsePositiveDetermination | AnalysisNotPlanned | FixNotPlanned
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
	}
)

// Event is a timestamped record of new information regarding the investigation
// and resolution of a potential vulnerability match.
type Event struct {
	// Timestamp is the time at which the event occurred.
	Timestamp time.Time `yaml:"timestamp"`

	// Type is a string that identifies the kind of event. This field is used to
	// determine how to unmarshal the Data field.
	Type string `yaml:"type"`

	// Data is the event-specific data. The type of this field is determined by the
	// Type field.
	Data interface{} `yaml:"data,omitempty"`
}

type partialEvent struct {
	Timestamp time.Time `yaml:"timestamp"`
	Type      string    `yaml:"type"`
	Data      yaml.Node
}

func (e *Event) UnmarshalYAML(v *yaml.Node) error {
	// Unmarshal the event type and timestamp as a "partial event" before unmarshalling the event-type-specific data.
	pe := partialEvent{}
	err := v.Decode(&pe)
	if err != nil {
		return err
	}

	var event Event

	switch pe.Type {
	case EventTypeDetection:
		event, err = decodeTypedEventData[Detection](pe)

	case EventTypeTruePositiveDetermination:
		event, err = decodeTypedEventData[TruePositiveDetermination](pe)

	case EventTypeFixed:
		event, err = decodeTypedEventData[Fixed](pe)

	case EventTypeFalsePositiveDetermination:
		event, err = decodeTypedEventData[FalsePositiveDetermination](pe)

	case EventTypeAnalysisNotPlanned:
		event, err = decodeTypedEventData[AnalysisNotPlanned](pe)

	case EventTypeFixNotPlanned:
		event, err = decodeTypedEventData[FixNotPlanned](pe)

	default:
		return fmt.Errorf("unrecognized event type %q, must be one of [%s]", pe.Type, strings.Join(EventTypes, ", "))
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

	data := new(T)
	err := pe.Data.Decode(data)
	if err != nil {
		return Event{}, err
	}
	event.Data = *data

	return event, nil
}

func (e Event) Validate(eventIndex int) error {
	return labelError(fmt.Sprintf("(index %d)", eventIndex),
		errors.Join(
			e.validateTimestamp(),
			e.validateType(),
			e.validateData(),
		),
	)
}

func (e Event) validateTimestamp() error {
	if e.Timestamp.IsZero() {
		return fmt.Errorf("timestamp must not be zero")
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
		// no validation needed currently

	case EventTypeFixNotPlanned:
		// no validation needed currently
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
