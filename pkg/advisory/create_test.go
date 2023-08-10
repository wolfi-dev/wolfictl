package advisory

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os/memfs"
)

func TestCreate(t *testing.T) {
	testTime := time.Date(2022, 9, 26, 0, 0, 0, 0, time.UTC)
	brotliExistingEventTime := time.Date(2022, 9, 15, 2, 40, 18, 0, time.UTC)

	tests := []struct {
		name        string
		req         Request
		wantErr     bool
		expectedDoc v2.Document
	}{
		{
			name: "first advisory for package",
			req: Request{
				Package:         "crane",
				VulnerabilityID: "CVE-2023-1234",
				Event: v2.Event{
					Timestamp: testTime,
					Type:      v2.EventTypeDetection,
					Data: v2.Detection{
						Type: v2.DetectionTypeManual,
					},
				},
			},
			wantErr: false,
			expectedDoc: v2.Document{
				SchemaVersion: v2.SchemaVersion,
				Package:       v2.Package{Name: "crane"},
				Advisories: v2.Advisories{
					{
						ID: "CVE-2023-1234",
						Events: []v2.Event{
							{
								Timestamp: testTime,
								Type:      v2.EventTypeDetection,
								Data: v2.Detection{
									Type: v2.DetectionTypeManual,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "updating existing advisory",
			req: Request{
				Package:         "brotli",
				VulnerabilityID: "CVE-2020-8927",
				Event: v2.Event{
					Timestamp: testTime,
					Type:      v2.EventTypeDetection,
					Data: v2.Detection{
						Type: v2.DetectionTypeManual,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "creating additional advisory for package",
			req: Request{
				Package:         "brotli",
				VulnerabilityID: "CVE-2023-1234",
				Event: v2.Event{
					Timestamp: testTime,
					Type:      v2.EventTypeDetection,
					Data: v2.Detection{
						Type: v2.DetectionTypeManual,
					},
				},
			},
			wantErr: false,
			expectedDoc: v2.Document{
				SchemaVersion: v2.SchemaVersion,
				Package:       v2.Package{Name: "brotli"},
				Advisories: v2.Advisories{
					{
						ID: "CVE-2020-8927",
						Events: []v2.Event{
							{
								Timestamp: brotliExistingEventTime,
								Type:      v2.EventTypeFixed,
								Data: v2.Fixed{
									FixedVersion: "1.0.9-r0",
								},
							},
						},
					},
					{
						ID: "CVE-2023-1234",
						Events: []v2.Event{
							{
								Timestamp: testTime,
								Type:      v2.EventTypeDetection,
								Data: v2.Detection{
									Type: v2.DetectionTypeManual,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "no events",
			req: Request{
				Package:         "brotli",
				VulnerabilityID: "CVE-2023-1234",
			},
			wantErr: true,
		},
		{
			name: "event type doesn't match data type",
			req: Request{
				Package:         "brotli",
				VulnerabilityID: "CVE-2023-1234",
				Event: v2.Event{
					Timestamp: testTime,
					Type:      v2.EventTypeDetection,
					Data: v2.Fixed{
						FixedVersion: "1.0.9-r0",
					},
				},
			},
			wantErr: true,
		},
	}

	dirFS := os.DirFS("testdata/create/advisories")
	memFS := memfs.New(dirFS)
	advisoryDocs, err := v2.NewIndex(memFS)
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Create(tt.req, CreateOptions{
				AdvisoryCfgs: advisoryDocs,
			})

			if (err != nil) != tt.wantErr {
				t.Errorf("Create() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err == nil {
				if diff := cmp.Diff(tt.expectedDoc, advisoryDocs.Select().WhereName(tt.req.Package).Configurations()[0]); diff != "" {
					t.Errorf("Create() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}
