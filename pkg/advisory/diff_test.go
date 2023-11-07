package advisory

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

var unixEpochTimestamp = v2.Timestamp(time.Unix(0, 0))

func TestDiff(t *testing.T) {
	cases := []struct {
		name               string
		expectedDiffResult IndexDiffResult
	}{
		{
			name:               "same",
			expectedDiffResult: IndexDiffResult{},
		},
		{
			name: "added-document",
			expectedDiffResult: IndexDiffResult{
				Added: []v2.Document{
					{
						SchemaVersion: v2.SchemaVersion,
						Package: v2.Package{
							Name: "ko",
						},
						Advisories: v2.Advisories{
							{
								ID: "CVE-2023-24535",
								Events: []v2.Event{
									{
										Timestamp: unixEpochTimestamp,
										Type:      v2.EventTypeTruePositiveDetermination,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "removed-document",
			expectedDiffResult: IndexDiffResult{
				Removed: []v2.Document{
					{
						SchemaVersion: v2.SchemaVersion,
						Package: v2.Package{
							Name: "ko",
						},
						Advisories: v2.Advisories{
							{
								ID: "CVE-2023-24535",
								Events: []v2.Event{
									{
										Timestamp: unixEpochTimestamp,
										Type:      v2.EventTypeTruePositiveDetermination,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "added-advisory",
			expectedDiffResult: IndexDiffResult{
				Modified: map[string]DocumentDiffResult{
					"ko": {
						Added: v2.Advisories{
							{
								ID: "CVE-2023-11111",
								Events: []v2.Event{
									{
										Timestamp: unixEpochTimestamp,
										Type:      v2.EventTypeTruePositiveDetermination,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "removed-advisory",
			expectedDiffResult: IndexDiffResult{
				Modified: map[string]DocumentDiffResult{
					"ko": {
						Removed: v2.Advisories{
							{
								ID: "CVE-2023-11111",
								Events: []v2.Event{
									{
										Timestamp: unixEpochTimestamp,
										Type:      v2.EventTypeTruePositiveDetermination,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "modified-advisory",
			expectedDiffResult: IndexDiffResult{
				Modified: map[string]DocumentDiffResult{
					"ko": {
						Modified: map[string]DiffResult{
							"CVE-2023-24535": {
								Added: v2.Advisory{
									ID: "CVE-2023-24535",
									Events: []v2.Event{
										{
											Timestamp: unixEpochTimestamp,
											Type:      v2.EventTypeFalsePositiveDetermination,
										},
									},
								},
								Removed: v2.Advisory{
									ID: "CVE-2023-24535",
									Events: []v2.Event{
										{
											Timestamp: unixEpochTimestamp,
											Type:      v2.EventTypeTruePositiveDetermination,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			aDir := filepath.Join("testdata", "diff", tt.name, "a")
			bDir := filepath.Join("testdata", "diff", tt.name, "b")
			aFsys := rwos.DirFS(aDir)
			bFsys := rwos.DirFS(bDir)
			aIndex, err := v2.NewIndex(aFsys)
			require.NoError(t, err)
			bIndex, err := v2.NewIndex(bFsys)
			require.NoError(t, err)

			diff := IndexDiff(aIndex, bIndex)

			if d := cmp.Diff(tt.expectedDiffResult, diff); d != "" {
				t.Errorf("unexpected diff result (-want +got):\n%s", d)
			}
		})
	}
}
