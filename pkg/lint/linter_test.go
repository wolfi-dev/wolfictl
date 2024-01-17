package lint

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func newTestLinterWithDir(path string) *Linter {
	return New(WithPath(filepath.Join("testdata", path)))
}

func newTestLinterWithFile(path string) *Linter {
	return New(WithPath(filepath.Join("testdata/files/", path)))
}

// EquateErrorsByString allows errors to be equated if their strings match but errors.Is returns false
func EquateErrorsByString() cmp.Option {
	return cmp.FilterValues(areConcreteErrors, cmp.Comparer(compareErrorsByString))
}

func areConcreteErrors(x, y interface{}) bool {
	_, ok1 := x.(error)
	_, ok2 := y.(error)
	return ok1 && ok2
}

func compareErrorsByString(x, y interface{}) bool {
	xe := x.(error) //nolint:errcheck // already asserted
	ye := y.(error) //nolint:errcheck // already asserted
	return xe.Error() == ye.Error()
}

func TestLinter_Dir(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    Result
		wantErr bool
	}{
		{
			name: "valid directory",
			path: "dirs/valid/",
			want: Result{},
		},
		{
			name:    "tld swap",
			path:    "dirs/tld-swap/",
			wantErr: false,
			want: Result{
				{
					File: "tld-swap",
					Errors: EvalRuleErrors{
						EvalRuleError{
							Rule: Rule{
								Name:        "uri-mimic",
								Description: "every config should use a consistent hostname",
								Severity:    SeverityError,
							},
							Error: fmt.Errorf("[uri-mimic]: \"test.org\" shares components with \"test.com\" (ERROR)"),
						},
					},
				},
			},
		},
		{
			name:    "similar domains",
			path:    "dirs/similar-domains/",
			wantErr: false,
			want: Result{
				{
					File: "libssh2",
					Errors: EvalRuleErrors{
						EvalRuleError{
							Rule: Rule{
								Name:        "uri-mimic",
								Description: "every config should use a consistent hostname",
								Severity:    SeverityError,
							},
							Error: fmt.Errorf("[uri-mimic]: \"www.libssh2.org\" too similar to \"www.libshh2.org\" (ERROR)"),
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			l := newTestLinterWithDir(tt.path)
			got, err := l.Lint(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("Lint() error = %v, wantErr %v", err, tt.wantErr)
			}

			if diff := cmp.Diff(got, tt.want, EquateErrorsByString(), cmpopts.IgnoreFields(Rule{}, "LintFunc")); diff != "" {
				t.Errorf("unexpected diff: %s\ngot: %+v", diff, got)
			}
		})
	}
}
