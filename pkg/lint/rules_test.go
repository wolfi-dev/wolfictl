package lint

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLinter_Rules(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		want    EvalResult
		wantErr bool
	}{
		{
			file: "missing-copyright.yaml",
			want: EvalResult{
				File: "missing-copyright",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "valid-copyright-header",
							Severity: SeverityInfo,
						},
						Error: fmt.Errorf("[valid-copyright-header]: copyright header is missing (INFO)"),
					},
				},
			},
			wantErr: false,
		},
		{
			file: "wrong-pipeline-fetch-uri.yaml",
			want: EvalResult{
				File: "wrong-pipeline-fetch-uri",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "valid-pipeline-fetch-uri",
							Severity: SeverityError,
						},
						Error: fmt.Errorf("[valid-pipeline-fetch-uri]: uri is invalid URL structure (ERROR)"),
					},
				},
			},
			wantErr: false,
		},
		{
			file: "wrong-pipeline-fetch-digest.yaml",
			want: EvalResult{
				File: "wrong-pipeline-fetch-digest",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "valid-pipeline-fetch-digest",
							Severity: SeverityError,
						},
						Error: fmt.Errorf("[valid-pipeline-fetch-digest]: expected-sha256 is not valid SHA256 (ERROR)"),
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			l := newTestLinterWithFile(tt.file)
			got, err := l.Lint()
			if (err != nil) != tt.wantErr {
				t.Errorf("Lint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Always should be a single element array.
			assert.Len(t, got, 1)

			g := got[0]

			// Ensure we're testing the right file.
			assert.Equal(t, tt.want.File, g.File)
			// Fast-fail if lengths don't match.
			assert.Len(t, g.Errors, len(tt.want.Errors))

			for i, e := range g.Errors {
				assert.Equal(t, e.Error, tt.want.Errors[i].Error, "Lint(): Error: got = %v, want %v", e.Error, tt.want.Errors[i].Error)
				assert.Equal(t, e.Rule.Name, tt.want.Errors[i].Rule.Name, "Lint(): Rule.Name: got = %v, want %v", e.Rule.Name, tt.want.Errors[i].Rule.Name)
				assert.Equal(t, e.Rule.Severity, tt.want.Errors[i].Rule.Severity, "Lint(): Rule.Severity: got = %v, want %v", e.Rule.Severity, tt.want.Errors[i].Rule.Severity)
			}
		})
	}
}
