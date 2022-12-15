package lint

import (
	"chainguard.dev/melange/pkg/build"
	"github.com/hashicorp/go-multierror"
)

// LintFunc is a function that lints a single configuration.
type LintFunc func(build.Configuration) error

// ConditionFunc is a function that checks if a rule should be executed.
type ConditionFunc func() bool

// Severity is the severity of a rule.
type Severity string

const (
	SeverityError   Severity = "ERROR"
	SeverityWarning Severity = "WARNING"
	SeverityInfo    Severity = "INFO"
)

// Rule represents a linter rule.
type Rule struct {
	// Name is the name of the rule.
	Name string

	// Description is the description of the rule.
	Description string

	// Severity is the severity of the rule.
	Severity Severity

	// LintFunc is the function that lints a single configuration.
	LintFunc LintFunc

	// ConditionFuncs is a list of and-conditioned functions that check if the rule should be executed.
	ConditionFuncs []ConditionFunc
}

// Rules is a list of Rule.
type Rules []Rule

// EvalResult represents the result of an evaluation for a single configuration.
type EvalResult struct {
	// File is the name of the file that was evaluated against.
	File string

	// Errors is a list of validation errors.
	Errors multierror.Error
}

// Result is a list of RuleResult.
type Result []EvalResult
