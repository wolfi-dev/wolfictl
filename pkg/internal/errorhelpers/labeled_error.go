package errorhelpers

import (
	"fmt"
)

type LabeledError struct {
	label string
	err   error
}

// Error returns the error as a message string (to implement the error
// interface).
func (l LabeledError) Error() string {
	return fmt.Sprintf("%s: %s", l.label, l.err.Error())
}

// Label returns the label for the error.
func (l LabeledError) Label() string {
	return l.label
}

// Unwrap returns the underlying error.
func (l LabeledError) Unwrap() error {
	return l.err
}

func LabelError(label string, err error) error {
	if err == nil {
		return nil
	}

	return &LabeledError{label, err}
}
