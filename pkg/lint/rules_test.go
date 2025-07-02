package lint

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinter_Rules(t *testing.T) {
	tests := []struct {
		name        string
		file        string
		minSeverity Severity
		matches     int
		want        EvalResult
		wantErr     bool
	}{
		{
			file:        "missing-copyright.yaml",
			minSeverity: SeverityInfo,
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
			matches: 1,
		},
		{
			file:        "forbidden-repository.yaml",
			minSeverity: SeverityWarning,
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
			matches: 1,
		},
		{
			file:        "forbidden-repository-tagged.yaml",
			minSeverity: SeverityWarning,
			want: EvalResult{
				File: "forbidden-repository-tagged",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "tagged-repository-in-environment-repos",
							Severity: SeverityError,
						},
						Error: fmt.Errorf("[tagged-repository-in-environment-repos]: repository \"@local ./foo\" is tagged (ERROR)"),
					},
				},
			},
			wantErr: false,
			matches: 1,
		},
		{
			file:        "forbidden-keyring.yaml",
			minSeverity: SeverityWarning,
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
			matches: 1,
		},
		{
			file:        "wrong-pipeline-fetch-uri.yaml",
			minSeverity: SeverityWarning,
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
			matches: 1,
		},
		{
			file:        "idn-homograph-attack.yaml",
			minSeverity: SeverityWarning,
			want: EvalResult{
				File: "idn-homograph-attack",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "valid-pipeline-fetch-uri",
							Severity: SeverityError,
						},
						Error: fmt.Errorf("[valid-pipeline-fetch-uri]: uri hostname \"downloads.xⅰph.org\" is invalid (ERROR)"),
					},
				},
			},
			wantErr: false,
			matches: 1,
		},
		{
			file:        "idn-homograph-attack-git-checkout.yaml",
			minSeverity: SeverityWarning,
			want: EvalResult{
				File: "idn-homograph-attack-git-checkout",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "valid-pipeline-fetch-uri",
							Severity: SeverityError,
						},
						Error: fmt.Errorf("[valid-pipeline-fetch-uri]: uri hostname \"downloads.xⅰph.org\" is invalid (ERROR)"),
					},
				},
			},
			wantErr: false,
			matches: 1,
		},
		{
			file:        "wrong-pipeline-fetch-digest.yaml",
			minSeverity: SeverityWarning,
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
			matches: 1,
		},
		{
			file:        "duplicated-package.yaml",
			minSeverity: SeverityWarning,
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
			matches: 1,
		},
		{
			file:        "bad-template-var.yaml",
			minSeverity: SeverityWarning,
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
			matches: 1,
		},
		{
			file:        "bad-version.yaml",
			minSeverity: SeverityWarning,
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
			matches: 1,
		},
		{
			file:        "wrong-pipeline-git-checkout-commit.yaml",
			minSeverity: SeverityWarning,
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
			matches: 1,
		},
		{
			file:        "missing-pipeline-git-checkout-commit.yaml",
			minSeverity: SeverityWarning,
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
			matches: 1,
		},
		{
			file:        "wrong-pipeline-git-checkout-tag.yaml",
			minSeverity: SeverityWarning,
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
			matches: 1,
		},
		{
			file:        "nolint.yaml",
			minSeverity: SeverityInfo,
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
			matches: 1,
		},
		{
			file:        "no-epoch.yaml",
			minSeverity: SeverityWarning,
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
			matches: 1,
		},
		{
			file:        "check-version-matches.yaml",
			minSeverity: SeverityWarning,
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
			matches: 1,
		},
		{
			file:        "check-subpipeline-version-matches.yaml",
			minSeverity: SeverityWarning,
			want: EvalResult{
				File: "check-subpipeline-version-matches",
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
			matches: 1,
		},
		{
			file:        "missing-github-update-git-checkout.yaml",
			minSeverity: SeverityWarning,
			want: EvalResult{
				File: "missing-github-update-git-checkout",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "git-checkout-must-use-github-updates",
							Severity: SeverityError,
						},
						Error: fmt.Errorf("[git-checkout-must-use-github-updates]: configure update.github/update.git when using git-checkout (ERROR)"),
					},
				},
			},
			wantErr: false,
			matches: 1,
		},
		{
			file:        "no-main-test.yaml",
			minSeverity: SeverityInfo,
			want: EvalResult{
				File: "no-main-test",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "valid-package-or-subpackage-test",
							Severity: SeverityInfo,
						},
						Error: fmt.Errorf("[valid-package-or-subpackage-test]: no main package or subpackage test found (INFO)"),
					},
				},
			},
			wantErr: false,
			matches: 1,
		},
		{
			// Validate rule is not triggered when min severity < rule severity
			file:        "no-main-test.yaml",
			minSeverity: SeverityWarning,
			want: EvalResult{
				File: "no-main-test",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "valid-package-or-subpackage-test",
							Severity: SeverityInfo,
						},
						Error: fmt.Errorf("[valid-package-or-subpackage-test]: no main package or subpackage test found (INFO)"),
					},
				},
			},
			wantErr: false,
			matches: 0,
		},
		{
			file:        "has-subpackage-test.yaml",
			minSeverity: SeverityInfo,
			want: EvalResult{
				File: "has-subpackage-test",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "valid-package-or-subpackage-test",
							Severity: SeverityInfo,
						},
						Error: fmt.Errorf("[valid-package-or-subpackage-test]: no main package or subpackage test found (INFO)"),
					},
				},
			},
			wantErr: false,
			matches: 0,
		},
		{
			file:        "update-disabled.yaml",
			minSeverity: SeverityInfo,
			want: EvalResult{
				File: "update-disabled",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "update-disabled-reason",
							Severity: SeverityWarning,
						},
						Error: fmt.Errorf("[update-disabled-reason]: auto-update is disabled but no reason is provided (WARNING)"),
					},
				},
			},
			wantErr: false,
			matches: 1,
		},
		{
			file:        "valid-update-schedule.yaml",
			minSeverity: SeverityWarning,
			want: EvalResult{
				File: "valid-update-schedule",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "valid-update-schedule",
							Severity: SeverityError,
						},
						Error: fmt.Errorf("[valid-update-schedule]: unsupported period: hourly (ERROR)"),
					},
				},
			},
			wantErr: false,
			matches: 1,
		},
		{
			file:        "invalid-spdx-license.yaml",
			minSeverity: SeverityWarning,
			want: EvalResult{
				File: "invalid-spdx-license",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "valid-spdx-license",
							Severity: SeverityError,
						},
						Error: fmt.Errorf("[valid-spdx-license]: license \"Apache License 2.0\" is not valid SPDX license (ERROR)"),
					},
				},
			},
			wantErr: true,
			matches: 1,
		},
		{
			file:        "background-process-no-redirect.yaml",
			minSeverity: SeverityWarning,
			want: EvalResult{
				File: "background-process-no-redirect",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "background-process-without-redirect",
							Severity: SeverityWarning,
						},
						Error: fmt.Errorf("[background-process-without-redirect]: background process missing output redirect: croc relay --ports=1234 & (WARNING)"),
					},
				},
			},
			wantErr: false,
			matches: 1,
		},
		{
			file:        "background-process-with-redirect.yaml",
			minSeverity: SeverityWarning,
			want:        EvalResult{},
			wantErr:     false,
			matches:     0,
		},
		{
			file:        "daemon-flag-no-redirect.yaml",
			minSeverity: SeverityWarning,
			want: EvalResult{
				File: "daemon-flag-no-redirect",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "background-process-without-redirect",
							Severity: SeverityWarning,
						},
						Error: fmt.Errorf("[background-process-without-redirect]: background process missing output redirect: croc relay --daemon (WARNING)"),
					},
				},
			},
			wantErr: false,
			matches: 1,
		},
                {
                        file:        "daemon-flag-with-redirect.yaml",
                        minSeverity: SeverityWarning,
                        want:        EvalResult{},
                        wantErr:     false,
                        matches:     0,
                },
               {
                       file:        "cut-d-flag.yaml",
                       minSeverity: SeverityWarning,
                       want:        EvalResult{},
                       wantErr:     false,
                       matches:     0,
               },
        }

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			ctx := context.Background()
			l := newTestLinterWithFile(tt.file)
			got, err := l.Lint(ctx, tt.minSeverity)
			assert.Nil(t, err, "Error in the linting process")

			// Always should be a single element array.
			require.Len(t, got, tt.matches)

			if tt.matches == 0 {
				return
			}

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
