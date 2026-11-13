package lint

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"

	"golang.org/x/exp/slices"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/chainguard-dev/clog"
	"github.com/wolfi-dev/wolfictl/pkg/melange"
)

// Linter represents a linter instance.
type Linter struct {
	// options are the options to configure the linter.
	options Options
}

// New initializes a new instance of Linter.
func New(opts ...Option) *Linter {
	o := Options{}
	for _, opt := range opts {
		opt(&o)
	}
	return &Linter{options: o}
}

// Lint evaluates all rules and returns the result.
func (l *Linter) Lint(ctx context.Context, minSeverity Severity) (Result, error) {
	log := clog.FromContext(ctx)
	rules := AllRules(l)

	namesToPkg, err := melange.ReadAllPackagesFromRepo(ctx, l.options.Path)
	if err != nil {
		return Result{}, err
	}

	// global shared between config files for rule evaluation :(
	seenHosts = map[string]bool{}

	results := make(Result, 0)

	// sort for consistent ordering
	sortedNames := []string{}
	for n := range namesToPkg {
		sortedNames = append(sortedNames, n)
	}

	sort.Strings(sortedNames)

	for _, name := range sortedNames {
		failedRules := make(EvalRuleErrors, 0)
		for _, rule := range rules {
			// Check if we should skip this rule.
			shouldEvaluate := true
			if len(rule.ConditionFuncs) > 0 {
				for _, cond := range rule.ConditionFuncs {
					if !cond() {
						shouldEvaluate = false
						break
					}
				}
			}

			// If one of the conditions is not met we skip the evaluation process.
			if !shouldEvaluate {
				log.Debugf("%s: skipping rule %s because condition is not met\n", name, rule.Name)
				continue
			}

			// Allow users to override rules when running lint command
			if slices.Contains(l.options.SkipRules, rule.Name) {
				log.Debugf("%s: skipping rule %s because --skip-rule flag set\n", name, rule.Name)
				continue
			}

			if slices.Contains(namesToPkg[name].NoLint, rule.Name) {
				log.Debugf("%s: skipping rule %s because file contains #nolint:%s\n", name, rule.Name, rule.Name)
				continue
			}

			// Evaluate the rule.
			if err := rule.LintFunc(namesToPkg[name].Config); err != nil {
				// Only add to failedRules if the severity is inclusive of the minSeverity
				if rule.Severity.Value <= minSeverity.Value {
					msg := fmt.Sprintf("[%s]: %s (%s)", rule.Name, err.Error(), rule.Severity.Name)

					line := errorLine(err)
					if line == 0 {
						// Fall back to the package block for errors that
						// aren't attributed to a specific line.
						line = lineOf(namesToPkg[name].Config.Root(), "package")
					}

					failedRules = append(failedRules, EvalRuleError{
						Rule:  rule,
						Error: fmt.Errorf("%s", msg),
						Line:  line,
					})
				}
			}
		}
		// If we have errors we append them to the result.
		if failedRules.WrapErrors() != nil {
			results = append(results, EvalResult{
				File:   name,
				Path:   filepath.Join(l.options.Path, namesToPkg[name].Filename),
				Errors: failedRules,
			})
		}
	}

	return results, nil
}

func (l *Linter) Print(ctx context.Context, result Result) {
	log := clog.FromContext(ctx)
	foundAny := false
	for _, res := range result {
		for _, e := range res.Errors {
			foundAny = true
			if e.Line > 0 {
				log.Errorf("Package: %s: %s:%d: %s", res.File, res.Path, e.Line, e.Error)
			} else {
				log.Errorf("Package: %s: %s", res.File, e.Error)
			}
		}
	}
	if !foundAny {
		log.Infof("No linting issues found!")
	}
}

// PrintRules prints the rules to stdout.
func (l *Linter) PrintRules(ctx context.Context) {
	log := clog.FromContext(ctx)
	log.Info("Available rules:")
	for _, rule := range AllRules(l) {
		log.Infof("* %s: %s\n", rule.Name, cases.Title(language.Und).String(rule.Description))
	}
}
