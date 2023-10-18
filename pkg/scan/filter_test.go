package scan

import (
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func TestFilterWithAdvisories(t *testing.T) {
	cases := []struct {
		name                  string
		result                *Result
		advisoryIndicesGetter func(t *testing.T) []*configs.Index[v2.Document]
		advisoryFilterSet     string
		expectedFindings      []*Finding
		errAssertion          assert.ErrorAssertionFunc
	}{
		{
			name:                  "nil result",
			result:                nil,
			advisoryIndicesGetter: getSingleAdvisoriesIndex,
			advisoryFilterSet:     "",
			expectedFindings:      nil,
			errAssertion:          assert.Error,
		},
		{
			name:                  "nil advisory index",
			result:                &Result{},
			advisoryIndicesGetter: func(_ *testing.T) []*configs.Index[v2.Document] { return nil },
			advisoryFilterSet:     "",
			expectedFindings:      nil,
			errAssertion:          assert.Error,
		},
		{
			name: "no filter set",
			result: &Result{
				TargetAPK: TargetAPK{
					Name:    "ko",
					Version: "42",
				},
				Findings: []*Finding{
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
			advisoryIndicesGetter: getSingleAdvisoriesIndex,
			advisoryFilterSet:     "",
			expectedFindings:      nil,
			errAssertion:          assert.Error,
		},
		{
			name: "filter set all",
			result: &Result{
				TargetAPK: TargetAPK{
					Name:    "ko",
					Version: "42",
				},
				Findings: []*Finding{
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
			advisoryIndicesGetter: getSingleAdvisoriesIndex,
			advisoryFilterSet:     "all",
			expectedFindings: []*Finding{
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
				Findings: []*Finding{
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
			advisoryIndicesGetter: getSingleAdvisoriesIndex,
			advisoryFilterSet:     "all",
			expectedFindings:      []*Finding{},
			errAssertion:          assert.NoError,
		},
		{
			name: "filter set resolved",
			result: &Result{
				TargetAPK: TargetAPK{
					Name:    "ko",
					Version: "42",
				},
				Findings: []*Finding{
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
			advisoryIndicesGetter: getSingleAdvisoriesIndex,
			advisoryFilterSet:     "resolved",
			expectedFindings: []*Finding{
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
				Findings: []*Finding{
					{
						Vulnerability: Vulnerability{
							ID:      "GHSA-abcd-abcd-abcd",
							Aliases: []string{"CVE-2000-22222"},
						},
					},
				},
			},
			advisoryIndicesGetter: getSingleAdvisoriesIndex,
			advisoryFilterSet:     "resolved",
			expectedFindings:      []*Finding{},
			errAssertion:          assert.NoError,
		},
		{
			name: "filter set resolved, via origin package",
			result: &Result{
				TargetAPK: TargetAPK{
					Name:              "some-ko-subpackage",
					Version:           "0.13.0-r4",
					OriginPackageName: "ko",
				},
				Findings: []*Finding{
					{
						Vulnerability: Vulnerability{
							ID: "GHSA-2h5h-59f5-c5x9",
						},
					},
				},
			},
			advisoryIndicesGetter: getSingleAdvisoriesIndex,
			advisoryFilterSet:     "resolved",
			expectedFindings:      []*Finding{},
			errAssertion:          assert.NoError,
		},
		{
			name: "filter set resolved, but fixed version not reached",
			result: &Result{
				TargetAPK: TargetAPK{
					Name:    "ko",
					Version: "0.13.0-r2",
				},
				Findings: []*Finding{
					{
						Vulnerability: Vulnerability{
							ID: "GHSA-2h5h-59f5-c5x9",
						},
					},
				},
			},
			advisoryIndicesGetter: getSingleAdvisoriesIndex,
			advisoryFilterSet:     "resolved",
			expectedFindings: []*Finding{
				{
					Vulnerability: Vulnerability{
						ID: "GHSA-2h5h-59f5-c5x9",
					},
				},
			},
			errAssertion: assert.NoError,
		},
		{
			name: "use multiple advisory indices",
			result: &Result{
				TargetAPK: TargetAPK{
					Name:    "ko",
					Version: "0.13.0-r2",
				},
				Findings: []*Finding{
					{
						Vulnerability: Vulnerability{
							ID: "GHSA-2h5h-59f5-c5x9", // In first advisories index (as fixed)
						},
					},
					{
						Vulnerability: Vulnerability{
							ID: "GHSA-bbbb-bbbb-bbbb", // In second advisories index (as true positive)
						},
					},
					{
						Vulnerability: Vulnerability{
							ID: "GHSA-cccc-cccc-cccc", // Not in any of the advisories indices
						},
					},
				},
			},
			advisoryIndicesGetter: getMultipleAdvisoriesIndices,
			advisoryFilterSet:     "all",
			expectedFindings: []*Finding{
				{
					Vulnerability: Vulnerability{
						ID: "GHSA-cccc-cccc-cccc",
					},
				},
			},
			errAssertion: assert.NoError,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			index := tt.advisoryIndicesGetter(t)

			var resultFindings []*Finding
			var err error
			assert.NotPanics(t, func() {
				resultFindings, err = FilterWithAdvisories(tt.result, index, tt.advisoryFilterSet)
			})
			tt.errAssertion(t, err)
			assert.Equal(t, tt.expectedFindings, resultFindings)
		})
	}
}

func getSingleAdvisoriesIndex(t *testing.T) []*configs.Index[v2.Document] {
	t.Helper()

	advFS := rwos.DirFS(path.Join("testdata", "advisories"))
	index, err := v2.NewIndex(advFS)
	if err != nil {
		t.Fatal(err)
	}

	return []*configs.Index[v2.Document]{index}
}

func getMultipleAdvisoriesIndices(t *testing.T) []*configs.Index[v2.Document] {
	t.Helper()

	var indices []*configs.Index[v2.Document]

	for _, dir := range []string{
		"advisories",
		"advisories-additional",
	} {
		advFS := rwos.DirFS(path.Join("testdata", dir))
		index, err := v2.NewIndex(advFS)
		if err != nil {
			t.Fatal(err)
		}
		indices = append(indices, index)
	}

	return indices
}
