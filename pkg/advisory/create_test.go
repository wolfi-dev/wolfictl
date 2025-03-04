package advisory

import (
	"context"
	"os"
	"testing"
	"time"

	advisoryapi "chainguard.dev/sdk/proto/platform/advisory/v1"
	apitest "chainguard.dev/sdk/proto/platform/advisory/v1/test"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os/memfs"
)

func TestCreate(t *testing.T) {
	testTime := v2.Timestamp(time.Date(2022, 9, 26, 0, 0, 0, 0, time.UTC))
	brotliExistingEventTime := v2.Timestamp(time.Date(2022, 9, 15, 2, 40, 18, 0, time.UTC))

	goodCGAID := "CGA-xoxo-xoxo-xoxo"
	usedCGAID := "CGA-abcd-abcd-abcd"

	advisoryClient := apitest.MockSecurityAdvisoryClient{
		OnListDocuments: []apitest.DocumentsOnList{{
			Given: &advisoryapi.DocumentFilter{
				Cves: []string{goodCGAID},
			},
			List: &advisoryapi.DocumentList{Items: []*advisoryapi.Document{}},
		}, {
			Given: &advisoryapi.DocumentFilter{
				Cves: []string{usedCGAID},
			},
			// This return value isn't checked, just that it exists. The details don't matter.
			List: &advisoryapi.DocumentList{Items: []*advisoryapi.Document{{
				Id: "package",
			}}},
		}},
	}

	tests := []struct {
		name        string
		req         Request
		cgaIDs      []string
		wantErr     bool
		expectedDoc v2.Document
	}{
		{
			name: "first advisory for package",
			req: Request{
				Package: "crane",
				Aliases: []string{"CVE-2023-1234"},
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
						ID:      goodCGAID, // will be ignored as we generate random ones
						Aliases: []string{"CVE-2023-1234"},
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
				Package: "brotli",
				Aliases: []string{"CVE-2020-8927"},
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
				Package: "brotli",
				Aliases: []string{"CVE-2023-1234"},
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
						ID:      "CGA-xoxo-xoxo-xoxo2", // will be ignored as we generate random ones
						Aliases: []string{"CVE-2023-1234"},
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
					{
						ID:      goodCGAID, // will be ignored as we generate random ones
						Aliases: []string{"CVE-2020-8927"},
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
				},
			},
		},
		{
			name: "creating additional advisory for package, sorted before existing advisory",
			req: Request{
				Package: "brotli",
				Aliases: []string{"CVE-2000-1234"},
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
						ID:      "CGA-xoxo-xoxo-xoxo2", // will be ignored as we generate random ones
						Aliases: []string{"CVE-2000-1234"},
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
					{
						ID:      goodCGAID, // will be ignored as we generate random ones
						Aliases: []string{"CVE-2020-8927"},
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
				},
			},
		},
		{
			name: "no events",
			req: Request{
				Package:    "brotli",
				AdvisoryID: goodCGAID,
			},
			wantErr: true,
		},
		{
			name: "event type doesn't match data type",
			req: Request{
				Package: "brotli",
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
		{
			name:   "generate a used CGA ID",
			cgaIDs: []string{usedCGAID, goodCGAID},
			req: Request{
				Package: "crane",
				Aliases: []string{"CVE-2023-1234"},
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
						ID:      goodCGAID, // will be ignored as we generate random ones
						Aliases: []string{"CVE-2023-1234"},
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
	}

	dirFS := os.DirFS("testdata/create/advisories")

	// Mock the API client init call.
	getAdvisoryClients = func(_ context.Context) (advisoryapi.Clients, error) {
		return apitest.MockSecurityAdvisoryClients{SecurityAdvisoryClient: advisoryClient}, nil
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sg := &StaticListIDGenerator{IDs: []string{goodCGAID}}
			// Use the test case CGA IDs, if provided.
			if len(tt.cgaIDs) > 0 {
				sg.IDs = tt.cgaIDs
			}
			DefaultIDGenerator = sg
			defer func() { DefaultIDGenerator = &RandomIDGenerator{} }()

			// We want a fresh memfs for each test case.
			fsys := memfs.New(dirFS)
			advisoryDocs, err := v2.NewIndex(context.Background(), fsys)
			require.NoError(t, err)

			err = Create(context.Background(), tt.req, CreateOptions{
				AdvisoryDocs: advisoryDocs,
			})

			if (err != nil) != tt.wantErr {
				t.Errorf("Create() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err == nil {
				diff := cmp.Diff(tt.expectedDoc, advisoryDocs.Select().WhereName(tt.req.Package).Configurations()[0], cmp.FilterPath(func(p cmp.Path) bool {
					// Check if the path is accessing the ID field within the Advisories slice.
					if len(p) < 2 {
						return false
					}
					if p[len(p)-1].String() == ".ID" {
						return true
					}
					return false
				}, cmp.Ignore()))
				if diff != "" {
					t.Errorf("Update() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}
