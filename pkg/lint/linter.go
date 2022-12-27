package lint

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/wolfi-dev/wolfictl/pkg/melange"
)

// Linter represents a linter instance.
type Linter struct {
	// options are the options to configure the linter.
	options Options

	// makefileBytes is storing the cached bytes of the Makefile
	// to avoid reading it multiple times.
	makefileBytes []byte

	// logger is the logger to use.
	logger *log.Logger
}

// New initializes a new instance of Linter.
func New(opts ...Option) *Linter {
	o := Options{}
	for _, opt := range opts {
		opt(&o)
	}
	return &Linter{
		options: o,
		logger:  log.New(log.Writer(), "", log.LstdFlags|log.Lmsgprefix),
	}
}

// Lint evaluates all rules and returns the result.
func (l *Linter) Lint() (Result, error) {
	rules := AllRules(l)

	filesToLint, err := melange.ReadAllPackagesFromRepo(l.options.Path)
	if err != nil {
		return Result{}, err
	}

	results := make(Result, 0)
	for name := range filesToLint {
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
				if l.options.Verbose {
					l.logger.Printf("%s: skipping rule %s because condition is not met\n", name, rule.Name)
				}
				continue
			}

			// Evaluate the rule.
			if err := rule.LintFunc(filesToLint[name]); err != nil {
				msg := fmt.Sprintf("[%s]: %s (%s)", rule.Name, err.Error(), rule.Severity)
				if l.options.Verbose {
					msg += fmt.Sprintf(" - (%s)", rule.Description)
				}

				failedRules = append(failedRules, EvalRuleError{
					Rule:  rule,
					Error: fmt.Errorf(msg),
				})
			}
		}
		// If we have errors we append them to the result.
		if failedRules.WrapErrors() != nil {
			results = append(results, EvalResult{
				File:   name,
				Errors: failedRules,
			})
		}
	}

	return results, nil
}

// Print prints the result to stdout.
func (l *Linter) Print(result Result) {
	foundAny := false
	for _, res := range result {
		if res.Errors.WrapErrors() != nil {
			foundAny = true
			l.logger.Printf("Package: %s: %s\n", res.File, res.Errors.WrapErrors())
		}
	}
	if !foundAny {
		l.logger.Println("No linting issues found!")
	}
}

// PrintRules prints the rules to stdout.
func (l *Linter) PrintRules() {
	l.logger.Println("Available rules:")
	for _, rule := range AllRules(l) {
		l.logger.Printf("* %s: %s\n", rule.Name, cases.Title(language.Und).String(rule.Description))
	}
}

// checkIfMakefileExists returns a ConditionFunc that checks if the Makefile exists.
func (l *Linter) checkIfMakefileExists() ConditionFunc {
	return func() bool {
		if _, err := os.Stat(filepath.Join(l.options.Path, "Makefile")); err != nil {
			return false
		}
		return true
	}
}

// readMakefile reads the Makefile from the file.
func (l *Linter) readMakefile() error {
	b, err := os.ReadFile(filepath.Join(l.options.Path, "Makefile"))
	if err != nil {
		return fmt.Errorf("failed to open Makefile: %w", err)
	}
	if len(b) == 0 {
		return fmt.Errorf("makefile is empty")
	}
	l.makefileBytes = b
	return nil
}

// checkMakefile checks if the given package name is exists in the Makefile.
func (l *Linter) checkMakefile(packageName string) (bool, error) {
	// Lazy load the Makefile.
	if l.makefileBytes == nil {
		if err := l.readMakefile(); err != nil {
			return false, err
		}
	}

	scanner := bufio.NewScanner(bytes.NewReader(l.makefileBytes))

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, fmt.Sprintf("$(eval $(call build-package,%s,", packageName)) {
			// We found the corresponding package in the Makefile.
			return true, nil
		}
	}
	// If we didn't find the package in the Makefile we return false.
	return false, nil
}
