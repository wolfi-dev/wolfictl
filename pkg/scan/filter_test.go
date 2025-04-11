package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
)

func TestFilterWithAdvisories(t *testing.T) {
	cases := []struct {
		name               string
		result             *Result
		advisoryGetterFunc func(t *testing.T) advisory.Getter
		advisoryFilterSet  string
		expectedFindings   []Finding
		errAssertion       assert.ErrorAssertionFunc
	}{
		{
			name:               "nil advisory getter",
			result:             &Result{},
			advisoryGetterFunc: func(_ *testing.T) advisory.Getter { return nil },
			advisoryFilterSet:  "",
			expectedFindings:   nil,
			errAssertion:       assert.Error,
		},
		{
			name: "no filter set",
			result: &Result{
				TargetAPK: TargetAPK{
					Name:    "ko",
					Version: "42",
				},
				Findings: []Finding{
					{
						Package: Package{
							Name:    "compliancebot",
							Version: "3000",
						},
						Vulnerability: Vulnerability{
							ID: "CVE-2023-1234",
						},
					},
				},
			},
			advisoryGetterFunc: getSingleAdvisoriesGetter,
			advisoryFilterSet:  "",
			expectedFindings:   nil,
			errAssertion:       assert.Error,
		},
		{
			name: "filter set all",
			result: &Result{
				TargetAPK: TargetAPK{
					Name:    "ko",
					Version: "42",
				},
				Findings: []Finding{
					{
						Vulnerability: Vulnerability{
							ID: "CVE-2023-1234",
						},
					},
					{
						Vulnerability: Vulnerability{
							ID: "CVE-1999-11111",
						},
					},
					{
						Vulnerability: Vulnerability{
							ID: "CVE-2000-22222",
						},
					},
					{
						Vulnerability: Vulnerability{
							ID: "GHSA-2h5h-59f5-c5x9",
						},
					},
				},
			},
			advisoryGetterFunc: getSingleAdvisoriesGetter,
			advisoryFilterSet:  "all",
			expectedFindings: []Finding{
				{
					Vulnerability: Vulnerability{
						ID: "CVE-2023-1234",
					},
				},
			},
			errAssertion: assert.NoError,
		},
		{
			name: "filter set all, via alias",
			result: &Result{
				TargetAPK: TargetAPK{
					Name:    "ko",
					Version: "42",
				},
				Findings: []Finding{
					{
						Vulnerability: Vulnerability{
							ID:      "GHSA-1234-1234-1234",
							Aliases: []string{"CVE-1999-11111"},
						},
					},
					{
						Vulnerability: Vulnerability{
							ID:      "GHSA-abcd-abcd-abcd",
							Aliases: []string{"CVE-2000-22222"},
						},
					},
				},
			},
			advisoryGetterFunc: getSingleAdvisoriesGetter,
			advisoryFilterSet:  "all",
			expectedFindings:   []Finding{},
			errAssertion:       assert.NoError,
		},
		{
			name: "filter set resolved",
			result: &Result{
				TargetAPK: TargetAPK{
					Name:    "ko",
					Version: "42",
				},
				Findings: []Finding{
					{
						Vulnerability: Vulnerability{
							ID: "CVE-2023-1234",
						},
					},
					{
						Vulnerability: Vulnerability{
							ID: "CVE-1999-11111",
						},
					},
					{
						Vulnerability: Vulnerability{
							ID: "CVE-2000-22222",
						},
					},
					{
						Vulnerability: Vulnerability{
							ID: "GHSA-2h5h-59f5-c5x9",
						},
						// Fixed advisories only work for type "apk"
						Package: Package{
							Type: "apk",
						},
					},
				},
			},
			advisoryGetterFunc: getSingleAdvisoriesGetter,
			advisoryFilterSet:  "resolved",
			expectedFindings: []Finding{
				{
					Vulnerability: Vulnerability{
						ID: "CVE-2023-1234",
					},
				},
				{
					Vulnerability: Vulnerability{
						ID: "CVE-1999-11111",
					},
				},
			},
			errAssertion: assert.NoError,
		},
		{
			name: "filter set resolved, via alias",
			result: &Result{
				TargetAPK: TargetAPK{
					Name:    "ko",
					Version: "42",
				},
				Findings: []Finding{
					{
						Vulnerability: Vulnerability{
							ID:      "GHSA-abcd-abcd-abcd",
							Aliases: []string{"CVE-2000-22222"},
						},
					},
				},
			},
			advisoryGetterFunc: getSingleAdvisoriesGetter,
			advisoryFilterSet:  "resolved",
			expectedFindings:   []Finding{},
			errAssertion:       assert.NoError,
		},
		{
			name: "filter set resolved, via origin package",
			result: &Result{
				TargetAPK: TargetAPK{
					Name:              "some-ko-subpackage",
					Version:           "0.13.0-r4",
					OriginPackageName: "ko",
				},
				Findings: []Finding{
					{
						Vulnerability: Vulnerability{
							ID: "GHSA-2h5h-59f5-c5x9",
						},
						// Fixed advisories only work for type "apk"
						Package: Package{
							Type: "apk",
							PURL: "purl-value",
						},
					},
				},
			},
			advisoryGetterFunc: getSingleAdvisoriesGetter,
			advisoryFilterSet:  "resolved",
			expectedFindings:   []Finding{},
			errAssertion:       assert.NoError,
		},
		{
			name: "filter set resolved, but fixed version not reached",
			result: &Result{
				TargetAPK: TargetAPK{
					Name:    "ko",
					Version: "0.13.0-r2",
				},
				Findings: []Finding{
					{
						Vulnerability: Vulnerability{
							ID: "GHSA-2h5h-59f5-c5x9",
						},
					},
				},
			},
			advisoryGetterFunc: getSingleAdvisoriesGetter,
			advisoryFilterSet:  "resolved",
			expectedFindings: []Finding{
				{
					Vulnerability: Vulnerability{
						ID: "GHSA-2h5h-59f5-c5x9",
					},
				},
			},
			errAssertion: assert.NoError,
		},
		{
			name: "use concluded advisory filter",
			result: &Result{
				TargetAPK: TargetAPK{
					Name:    "ko",
					Version: "0.13.0-r2",
				},
				Findings: []Finding{
					{
						Vulnerability: Vulnerability{
							ID: "CVE-2023-1234",
						},
					},
					{
						Vulnerability: Vulnerability{
							ID: "CVE-1999-11111",
						},
					},
					{
						Vulnerability: Vulnerability{
							ID: "CVE-2000-22222",
						},
					},
					{
						Vulnerability: Vulnerability{
							ID: "CVE-2003-55555",
						},
					},
				},
			},
			advisoryGetterFunc: getSingleAdvisoriesGetter,
			advisoryFilterSet:  "concluded",
			expectedFindings: []Finding{
				{
					Vulnerability: Vulnerability{
						ID: "CVE-2023-1234",
					},
				},
				{
					Vulnerability: Vulnerability{
						ID: "CVE-1999-11111",
					},
				},
				{
					Vulnerability: Vulnerability{
						ID: "CVE-2003-55555",
					},
				},
			},
			errAssertion: assert.NoError,
		},
		{
			name: "use concluded advisory filter with a newer version",
			result: &Result{
				TargetAPK: TargetAPK{
					Name:    "ko",
					Version: "0.13.0-r30",
				},
				Findings: []Finding{
					{
						Vulnerability: Vulnerability{
							ID: "GHSA-2h5h-59f5-c5x9",
						},
						// Fixed advisories only work for type "apk"
						Package: Package{
							Type: "apk",
						},
					},
					{
						Vulnerability: Vulnerability{
							ID: "CVE-1999-11111",
						},
					},
				},
			},
			advisoryGetterFunc: getSingleAdvisoriesGetter,
			advisoryFilterSet:  "concluded",
			expectedFindings: []Finding{
				{
					Vulnerability: Vulnerability{
						ID: "CVE-1999-11111",
					},
				},
			},
			errAssertion: assert.NoError,
		},
		{
			name: "resolved advisory filter only filters type apk",
			result: &Result{
				TargetAPK: TargetAPK{
					Name:    "ko",
					Version: "0.13.0-r30",
				},
				Findings: []Finding{
					{
						Vulnerability: Vulnerability{
							ID: "GHSA-2h5h-59f5-c5x9",
						},
						Package: Package{
							Type: "go-module",
							PURL: "purl-value",
						},
					},
					{
						Vulnerability: Vulnerability{
							ID: "CVE-1999-11111",
						},
					},
				},
			},
			advisoryGetterFunc: getSingleAdvisoriesGetter,
			advisoryFilterSet:  "concluded",
			expectedFindings: []Finding{
				{
					Vulnerability: Vulnerability{
						ID: "GHSA-2h5h-59f5-c5x9",
					},
					Package: Package{
						Type: "go-module",
						PURL: "purl-value",
					},
				},
				{
					Vulnerability: Vulnerability{
						ID: "CVE-1999-11111",
					},
				},
			},
			errAssertion: assert.NoError,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()

			g := tt.advisoryGetterFunc(t)

			var resultFindings []Finding
			var err error
			assert.NotPanics(t, func() {
				resultFindings, err = FilterWithAdvisories(ctx, *tt.result, g, tt.advisoryFilterSet)
			})
			tt.errAssertion(t, err)

			if diff := cmp.Diff(tt.expectedFindings, resultFindings); diff != "" {
				t.Errorf("unexpected findings: %s", diff)
			}
		})
	}
}

func getSingleAdvisoriesGetter(t *testing.T) advisory.Getter {
	t.Helper()

	return advisory.NewFSGetter(os.DirFS(filepath.Join("testdata", "advisories")))
}
