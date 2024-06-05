package triage

import (
	"errors"

	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
)

// ErrNoConclusion is the sentinel error returned by a Triager when it cannot
// reach a conclusion.
var ErrNoConclusion = errors.New("no triage conclusion was reached")

type ConclusionType int

const (
	Unknown ConclusionType = iota
	TruePositive
	FalsePositive
)

// Conclusion represents a triager conclusion for a single finding.
type Conclusion struct {
	Type   ConclusionType
	Reason interface{}
}

// EventTypeFromConclusions returns the advisory event type that should be used
// to capture the conclusions as an advisory request.
//
// If all findings are false positives, the returned request's event type will
// reflect a false positive.
//
// If any finding is a true positive, the returned request's event type will
// reflect a true positive. If no conclusions were reached, the returned event
// type will be an empty string.
func EventTypeFromConclusions(conclusions []Conclusion) string {
	allAreFalsePositives := true

	for _, c := range conclusions {
		switch c.Type {
		case TruePositive:
			return v2.EventTypeTruePositiveDetermination

		case Unknown:
			allAreFalsePositives = false
		}
	}

	if allAreFalsePositives {
		return v2.EventTypeFalsePositiveDetermination
	}

	return ""
}
