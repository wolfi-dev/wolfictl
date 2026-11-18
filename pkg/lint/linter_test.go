package lint

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// prefer-git-checkout warns on every fetch pipeline, which most fixtures use, so
// skip it by default to keep each fixture focused on the rule it's testing.
var defaultTestSkipRules = []string{"prefer-git-checkout"}

func newTestLinterWithDir(path string) *Linter {
	return New(WithPath(filepath.Join("testdata", path)), WithSkipRules(defaultTestSkipRules))
}

func newTestLinterWithFile(path string) *Linter {
	return New(WithPath(filepath.Join("testdata/files/", path)), WithSkipRules(defaultTestSkipRules))
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
					Path: "testdata/dirs/tld-swap/tld-swap.yaml",
					Errors: EvalRuleErrors{
						EvalRuleError{
							Rule: Rule{
								Name:        "uri-mimic",
								Description: "every config should use a consistent hostname",
								Severity:    SeverityError,
							},
							Error: fmt.Errorf("[uri-mimic]: \"test.org\" shares components with \"test.com\" (ERROR)"),
							Line:  15,
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
					Path: "testdata/dirs/similar-domains/libssh2.yaml",
					Errors: EvalRuleErrors{
						EvalRuleError{
							Rule: Rule{
								Name:        "uri-mimic",
								Description: "every config should use a consistent hostname",
								Severity:    SeverityError,
							},
							Error: fmt.Errorf("[uri-mimic]: \"www.libssh2.org\" too similar to \"www.libshh2.org\" (ERROR)"),
							Line:  14,
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
			got, err := l.Lint(ctx, SeverityWarning)
			if (err != nil) != tt.wantErr {
				t.Errorf("Lint() error = %v, wantErr %v", err, tt.wantErr)
			}

			if diff := cmp.Diff(got, tt.want, EquateErrorsByString(), cmpopts.IgnoreFields(Rule{}, "LintFunc")); diff != "" {
				t.Errorf("unexpected diff: %s\ngot: %+v", diff, got)
			}
		})
	}
}

func TestLinter_Print(t *testing.T) {
	var buf bytes.Buffer
	ctx := clog.WithLogger(context.Background(), clog.NewLogger(slog.New(slog.NewTextHandler(&buf, nil))))

	l := newTestLinterWithFile("bad-version.yaml")
	result, err := l.Lint(ctx, SeverityWarning)
	require.NoError(t, err)

	l.Print(ctx, result)

	assert.Contains(t, buf.String(), `msg="Package: bad-version: testdata/files/bad-version.yaml:3: [bad-version]: invalid version 1.0.0rc1, could not parse (ERROR)"`)
}
