package v2

import (
	"fmt"
)

type labeledError struct {
	label string
	err   error
}

// Error returns the error as a message string (to implement the error
// interface).
func (l labeledError) Error() string {
	return fmt.Sprintf("%s: %s", l.label, l.err.Error())
}

// Label returns the label for the error.
func (l labeledError) Label() string {
	return l.label
}

// Unwrap returns the underlying error.
func (l labeledError) Unwrap() error {
	return l.err
}

func labelError(label string, err error) error {
	if err == nil {
		return nil
	}

	return &labeledError{label, err}
}
