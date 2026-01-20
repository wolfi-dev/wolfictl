package lint

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"chainguard.dev/melange/pkg/config"
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
			file:        "update-identifier-not-matching-git-checkout-repository.yaml",
			minSeverity: SeverityError,
			want: EvalResult{
				File: "update-identifier-not-matching-git-checkout-repository",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "update-identifier-must-match-git-repository",
							Severity: SeverityError,
						},
						Error: fmt.Errorf("[update-identifier-must-match-git-repository]: update identifier does not match the repository URI (ERROR)"),
					},
				},
			},
			wantErr: false,
			matches: 1,
		},
		{
			file:        "update-identifier-not-matching-git-checkout-repository-nolint.yaml",
			minSeverity: SeverityError,
			want: EvalResult{
				File:   "update-identifier-not-matching-git-checkout-repository-nolint",
				Errors: EvalRuleErrors{},
			},
			wantErr: false,
			matches: 0,
		},
		{
			file:        "update-identifier-matching-git-checkout-repository.yaml",
			minSeverity: SeverityError,
			want: EvalResult{
				File:   "update-identifier-matching-git-checkout-repository",
				Errors: EvalRuleErrors{},
			},
			wantErr: false,
			matches: 0,
		},
		{
			file:        "update-identifier-matching-git-checkout-repository-mixed-case.yaml",
			minSeverity: SeverityError,
			want: EvalResult{
				File:   "update-identifier-matching-git-checkout-repository-mixed-case",
				Errors: EvalRuleErrors{},
			},
			wantErr: false,
			matches: 0,
		},
		{
			file:        "update-identifier-matching-git-checkout-repository-multiple-pipelines.yaml",
			minSeverity: SeverityError,
			want: EvalResult{
				File:   "update-identifier-matching-git-checkout-repository-multiple-pipelines",
				Errors: EvalRuleErrors{},
			},
			wantErr: false,
			matches: 0,
		},
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
			file:        "background-process-multiline-no-redirect.yaml",
			minSeverity: SeverityWarning,
			want: EvalResult{
				File: "background-process-multiline-no-redirect",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "background-process-without-redirect",
							Severity: SeverityWarning,
						},
						Error: fmt.Errorf("[background-process-without-redirect]: background process missing output redirect: coredns & (WARNING)"),
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
			file:        "double-ampersand-valid.yaml",
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
			file:        "avahi-no-daemon.yaml",
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
		// var-transform tests
		{
			file:        "var-transform-unused.yaml",
			minSeverity: SeverityWarning,
			want: EvalResult{
				File: "var-transform-unused",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "unused-var-transform",
							Severity: SeverityWarning,
						},
						Error: fmt.Errorf("[unused-var-transform]: var-transform creates unused variable \"unused-version\" (WARNING)"),
					},
				},
			},
			wantErr: false,
			matches: 1,
		},
		{
			file:        "var-transform-used.yaml",
			minSeverity: SeverityWarning,
			want:        EvalResult{},
			wantErr:     false,
			matches:     0,
		},
		{
			file:        "var-transform-multiple-partial-unused.yaml",
			minSeverity: SeverityWarning,
			want: EvalResult{
				File: "var-transform-multiple-partial-unused",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "unused-var-transform",
							Severity: SeverityWarning,
						},
						Error: fmt.Errorf("[unused-var-transform]: var-transform creates unused variables [\"unused-name\" \"another-unused\"] (WARNING)"),
					},
				},
			},
			wantErr: false,
			matches: 1,
		},
		{
			file:        "var-transform-used-in-subpackage.yaml",
			minSeverity: SeverityWarning,
			want:        EvalResult{},
			wantErr:     false,
			matches:     0,
		},
		{
			file:        "var-transform-used-in-with.yaml",
			minSeverity: SeverityWarning,
			want:        EvalResult{},
			wantErr:     false,
			matches:     0,
		},
		{
			file:        "var-transform-used-in-test-env.yaml",
			minSeverity: SeverityWarning,
			want:        EvalResult{},
			wantErr:     false,
			matches:     0,
		},
		{
			file:        "var-transform-used-in-test-packages.yaml",
			minSeverity: SeverityWarning,
			want:        EvalResult{},
			wantErr:     false,
			matches:     0,
		},
		{
			file:        "var-transform-chained-second-unused.yaml",
			minSeverity: SeverityWarning,
			want: EvalResult{
				File: "var-transform-chained-second-unused",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "unused-var-transform",
							Severity: SeverityWarning,
						},
						Error: fmt.Errorf("[unused-var-transform]: var-transform creates unused variable \"second-transform-unused\" (WARNING)"),
					},
				},
			},
			wantErr: false,
			matches: 1,
		},
		{
			file:        "var-transform-chained-both-used.yaml",
			minSeverity: SeverityWarning,
			want:        EvalResult{},
			wantErr:     false,
			matches:     0,
		},
		{
			file:        "var-transform-wrong-syntax-not-matched.yaml",
			minSeverity: SeverityWarning,
			want: EvalResult{
				File: "var-transform-wrong-syntax-not-matched",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "unused-var-transform",
							Severity: SeverityWarning,
						},
						Error: fmt.Errorf("[unused-var-transform]: var-transform creates unused variable \"my-version\" (WARNING)"),
					},
				},
			},
			wantErr: false,
			matches: 1,
		},
		{
			file:        "var-transform-used-in-runtime-deps.yaml",
			minSeverity: SeverityWarning,
			want:        EvalResult{},
			wantErr:     false,
			matches:     0,
		},
		{
			file:        "var-transform-used-in-env-packages.yaml",
			minSeverity: SeverityWarning,
			want:        EvalResult{},
			wantErr:     false,
			matches:     0,
		},
		{
			file:        "var-transform-chained-first-only-in-second.yaml",
			minSeverity: SeverityWarning,
			want:        EvalResult{},
			wantErr:     false,
			matches:     0,
		},
		// fetch-templating tests
		{
			file:        "fetch-templating-single-untemplated.yaml",
			minSeverity: SeverityWarning,
			want: EvalResult{
				File: "fetch-templating-single-untemplated",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "fetch-templating",
							Severity: SeverityWarning,
						},
						Error: fmt.Errorf("[fetch-templating]: source lacks templated variables: (fetch URL) https://example.com/package-1.2.3.tar.gz (WARNING)"),
					},
				},
			},
			wantErr: false,
			matches: 1,
		},
		{
			file:        "fetch-templating-single-templated.yaml",
			minSeverity: SeverityWarning,
			want:        EvalResult{},
			wantErr:     false,
			matches:     0,
		},
		{
			file:        "fetch-templating-multiple-no-template.yaml",
			minSeverity: SeverityWarning,
			want: EvalResult{
				File: "fetch-templating-multiple-no-template",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "fetch-templating",
							Severity: SeverityWarning,
						},
						Error: fmt.Errorf("[fetch-templating]: no templated variables found in any sources:\n- fetch URL: https://example.com/package-1.2.3.tar.gz\n- git tag: v1.2.3\nAt least one origin should use templates like ${{package.version}} to avoid version drift (WARNING)"),
					},
				},
			},
			wantErr: false,
			matches: 1,
		},
		{
			file:        "fetch-templating-multiple-with-template.yaml",
			minSeverity: SeverityWarning,
			want:        EvalResult{},
			wantErr:     false,
			matches:     0,
		},
		{
			file:        "fetch-templating-hardcoded-version.yaml",
			minSeverity: SeverityWarning,
			want: EvalResult{
				File: "fetch-templating-hardcoded-version",
				Errors: EvalRuleErrors{
					{
						Rule: Rule{
							Name:     "fetch-templating",
							Severity: SeverityWarning,
						},
						Error: fmt.Errorf("[fetch-templating]: fetch URL contains hardcoded package version '1.2.3' for 'fetch-templating-hardcoded-version': https://example.com/fetch-templating-hardcoded-version-1.2.3.tar.gz; check whether this should be derived from ${{package.version}} (or a transform) (WARNING)"),
					},
				},
			},
			wantErr: false,
			matches: 1,
		},
		{
			file:        "fetch-templating-git-tag-templated.yaml",
			minSeverity: SeverityWarning,
			want:        EvalResult{},
			wantErr:     false,
			matches:     0,
		},
		{
			file:        "fetch-templating-update-disabled.yaml",
			minSeverity: SeverityWarning,
			want:        EvalResult{},
			wantErr:     false,
			matches:     0,
		},
		{
			file:        "fetch-templating-vars-version.yaml",
			minSeverity: SeverityWarning,
			want:        EvalResult{},
			wantErr:     false,
			matches:     0,
		},
		{
			file:        "fetch-templating-manual-updates.yaml",
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
				assert.Equal(t, tt.want.Errors[i].Error, e.Error, "Lint(): Error: got = %v, want %v", e.Error, tt.want.Errors[i].Error)
				assert.Equal(t, tt.want.Errors[i].Rule.Name, e.Rule.Name, "Lint(): Rule.Name: got = %v, want %v", e.Rule.Name, tt.want.Errors[i].Rule.Name)
				assert.Equal(t, tt.want.Errors[i].Rule.Severity, e.Rule.Severity, "Lint(): Rule.Severity: got = %v, want %v", e.Rule.Severity, tt.want.Errors[i].Rule.Severity)
			}
		})
	}
}

func TestIdentifierFromRepoURI(t *testing.T) {
	cases := []struct {
		name     string
		expected string
	}{
		{
			name:     "https://github.com/wolfi-dev/os",
			expected: "wolfi-dev/os",
		},
		{
			name:     "https://github.com/wolfi-dev/os/",
			expected: "wolfi-dev/os",
		},
		{
			name:     "https://github.com/wolfi-dev/os.git",
			expected: "wolfi-dev/os",
		},
		{
			name:     "https://github.com/wolfi-dev/os.git/",
			expected: "wolfi-dev/os",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := identifierFromRepoURI(c.name)
			if got != c.expected {
				assert.Equal(t, c.expected, got, "Error: got = %v, want %v", got, c.expected)
			}
		})
	}
}

func TestPickPipelinesUsing(t *testing.T) {
	cases := []struct {
		name      string
		pipelines []config.Pipeline
		expected  int
	}{
		{
			name:      "single pipeline that match",
			pipelines: []config.Pipeline{{Uses: "desired"}},
			expected:  1,
		},
		{
			name:      "single pipeline that do not match",
			pipelines: []config.Pipeline{{Uses: "skipped"}},
			expected:  0,
		},
		{
			name:      "multiple pipelines that all match",
			pipelines: []config.Pipeline{{Uses: "desired"}, {Uses: "desired"}, {Uses: "desired"}},
			expected:  3,
		},
		{
			name:      "multiple pipelines that some match",
			pipelines: []config.Pipeline{{Uses: "skipped"}, {Uses: "desired"}, {Uses: "desired"}},
			expected:  2,
		},
		{
			name:      "multiple pipelines that none match",
			pipelines: []config.Pipeline{{Uses: "skipped"}, {Uses: "skipped"}, {Uses: "skipped"}},
			expected:  0,
		},
		{
			name:      "no pipelines",
			pipelines: []config.Pipeline{},
			expected:  0,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pipelines := pickPipelinesUsing("desired", c.pipelines)
			if len(pipelines) != c.expected {
				assert.Equal(t, c.expected, len(pipelines), "Error: got %d pipelines but expected %d", len(c.pipelines), c.expected)
			}
		})
	}
}
