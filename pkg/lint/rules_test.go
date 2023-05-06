package lint

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			file: "forbidden-repository.yaml",
			want: EvalResult{
				File: "forbidden-repository",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "forbidden-repository-used",
							Severity: SeverityError,
						},
						Error: fmt.Errorf("[forbidden-repository-used]: forbidden repository https://packages.wolfi.dev/os is used (ERROR)"),
					},
				},
			},
			wantErr: false,
		},
		{
			file: "forbidden-keyring.yaml",
			want: EvalResult{
				File: "forbidden-keyring",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "forbidden-keyring-used",
							Severity: SeverityError,
						},
						Error: fmt.Errorf("[forbidden-keyring-used]: forbidden keyring https://packages.wolfi.dev/os/wolfi-signing.rsa.pub is used (ERROR)"),
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
		{
			file: "duplicated-package.yaml",
			want: EvalResult{
				File: "duplicated-package",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "no-repeated-deps",
							Severity: SeverityError,
						},
						Error: fmt.Errorf("[no-repeated-deps]: package foo is duplicated in environment (ERROR)"),
					},
				},
			},
			wantErr: false,
		},
		{
			file: "bad-template-var.yaml",
			want: EvalResult{
				File: "bad-template-var",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "bad-template-var",
							Severity: SeverityError,
						},
						Error: fmt.Errorf("[bad-template-var]: package contains likely incorrect template var $pkgdir (ERROR)"),
					},
				},
			},
			wantErr: false,
		},
		{
			file: "bad-version.yaml",
			want: EvalResult{
				File: "bad-version",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "bad-version",
							Severity: SeverityError,
						},
						Error: fmt.Errorf("[bad-version]: invalid version 1.0.0rc1, could not parse (ERROR)"),
					},
				},
			},
		},
		{
			file: "wrong-pipeline-git-checkout-commit.yaml",
			want: EvalResult{
				File: "wrong-pipeline-git-checkout-commit",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "valid-pipeline-git-checkout-commit",
							Severity: SeverityError,
						},
						Error: fmt.Errorf("[valid-pipeline-git-checkout-commit]: expected-commit is not valid SHA1 (ERROR)"),
					},
				},
			},
			wantErr: false,
		},
		{
			file: "missing-pipeline-git-checkout-commit.yaml",
			want: EvalResult{
				File: "missing-pipeline-git-checkout-commit",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "valid-pipeline-git-checkout-commit",
							Severity: SeverityError,
						},
						Error: fmt.Errorf("[valid-pipeline-git-checkout-commit]: expected-commit is missing (ERROR)"),
					},
				},
			},
			wantErr: false,
		},
		{
			file: "wrong-pipeline-git-checkout-tag.yaml",
			want: EvalResult{
				File: "wrong-pipeline-git-checkout-tag",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "valid-pipeline-git-checkout-tag",
							Severity: SeverityError,
						},
						Error: fmt.Errorf("[valid-pipeline-git-checkout-tag]: tag is missing (ERROR)"),
					},
				},
			},
			wantErr: false,
		},
		{
			file: "nolint.yaml",
			want: EvalResult{
				File: "nolint",
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
			file: "no-epoch.yaml",
			want: EvalResult{
				File: "no-epoch",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "contains-epoch",
							Severity: SeverityError,
						},
						Error: fmt.Errorf("[contains-epoch]: config testdata/files/no-epoch.yaml has no package.epoch (ERROR)"),
					},
				},
			},
			wantErr: false,
		},
		{
			file: "check-version-matches.yaml",
			want: EvalResult{
				File: "check-version-matches",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "check-when-version-changes",
							Severity: SeverityError,
						},
						Error: errors.New("[check-when-version-changes]: version in comment: 1.0.0 does not match version in package: 1.0.1, check that it can be updated and update the comment (ERROR)"),
					},
				},
			},
			wantErr: false,
		},
		{
			file: "check-subpipeline-version-matches.yaml",
			want: EvalResult{
				File: "check-version-matches",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "check-when-version-changes",
							Severity: SeverityError,
						},
						Error: errors.New("[check-when-version-changes]: version in comment: 0.8.0 does not match version in package: 0.9.0, check that it can be updated and update the comment (ERROR)"),
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
			require.Len(t, got, 1)

			g := got[0]

			// Ensure we're testing the right file.
			assert.Equal(t, tt.want.File, g.File)
			// Fast-fail if lengths don't match.
			require.Len(t, g.Errors, len(tt.want.Errors))

			for i, e := range g.Errors {
				assert.Equal(t, e.Error, tt.want.Errors[i].Error, "Lint(): Error: got = %v, want %v", e.Error, tt.want.Errors[i].Error)
				assert.Equal(t, e.Rule.Name, tt.want.Errors[i].Rule.Name, "Lint(): Rule.Name: got = %v, want %v", e.Rule.Name, tt.want.Errors[i].Rule.Name)
				assert.Equal(t, e.Rule.Severity, tt.want.Errors[i].Rule.Severity, "Lint(): Rule.Severity: got = %v, want %v", e.Rule.Severity, tt.want.Errors[i].Rule.Severity)
			}
		})
	}
}
