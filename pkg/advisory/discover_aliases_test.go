package advisory

import (
	"context"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os/memfs"
)

func TestDiscoverAliases(t *testing.T) {
	cases := []struct {
		name                    string
		selectedPackage         string
		expectedUpdatedDocument v2.Document
		wantErr                 bool
	}{
		{
			name:            "find GHSA alias for a CVE",
			selectedPackage: "scenario-1",
			expectedUpdatedDocument: v2.Document{
				SchemaVersion: v2.SchemaVersion,
				Package: v2.Package{
					Name: "scenario-1",
				},
				Advisories: v2.Advisories{
					{
						ID:      "CGA-xoxo-xoxo-xoxo",
						Aliases: []string{"CVE-2222-2222", "GHSA-2222-2222-2222"},
					},
				},
			},
		},
		{
			name:            "find CVE for GHSA advisory ID and move GHSA ID to aliases",
			selectedPackage: "scenario-2",
			expectedUpdatedDocument: v2.Document{
				SchemaVersion: v2.SchemaVersion,
				Package: v2.Package{
					Name: "scenario-2",
				},
				Advisories: v2.Advisories{
					{
						ID:      "CGA-xoxo-xoxo-xoxo",
						Aliases: []string{"CVE-2222-2222", "GHSA-2222-2222-2222"},
					},
				},
			},
		},
		{
			name:            "no-op for non-CVE, non-GHSA advisory ID",
			selectedPackage: "scenario-3",
			expectedUpdatedDocument: v2.Document{
				SchemaVersion: "2", // i.e. doesn't get updated
				Package: v2.Package{
					Name: "scenario-3",
				},
				Advisories: v2.Advisories{
					{
						ID: "FOO-2222-2222",
					},
				},
			},
		},
		{
			name:            "no-op for CVE advisory ID with no discoverable aliases",
			selectedPackage: "scenario-4",
			expectedUpdatedDocument: v2.Document{
				SchemaVersion: "2", // i.e. doesn't get updated
				Package: v2.Package{
					Name: "scenario-4",
				},
				Advisories: v2.Advisories{
					{
						ID:      "CGA-xoxo-xoxo-xoxo",
						Aliases: []string{"CVE-4444-4444"},
					},
				},
			},
		},
		{
			name:            "no-op for GHSA advisory ID with no discoverable aliases",
			selectedPackage: "scenario-5",
			expectedUpdatedDocument: v2.Document{
				SchemaVersion: "2", // i.e. doesn't get updated
				Package: v2.Package{
					Name: "scenario-5",
				},
				Advisories: v2.Advisories{
					{
						ID:      "CGA-xoxo-xoxo-xoxo",
						Aliases: []string{"GHSA-3333-3333-3333"},
					},
				},
			},
		},
		{
			name:            "advisory ID changing to a CVE necessitates a re-sort of advisories",
			selectedPackage: "scenario-6",
			expectedUpdatedDocument: v2.Document{
				SchemaVersion: v2.SchemaVersion,
				Package: v2.Package{
					Name: "scenario-6",
				},
				Advisories: v2.Advisories{
					{
						ID: "CGA-honk-xoxo-xoxo",
						Aliases: []string{
							"CVE-1111-1111",
							"GHSA-5555-5555-5555",
						},
					},
					{
						ID: "CGA-xoxo-xoxo-xoxo",
						Aliases: []string{
							"GHSA-3333-3333-3333",
						},
					},
				},
			},
		},
		{
			name:            "advisory ID changing to a CVE creates a duplicate advisory ID, which should error out",
			selectedPackage: "scenario-7",
			wantErr:         true,
		},
	}

	mockAF := &mockAliasFinder{
		cveByGHSA: map[string]string{
			"GHSA-2222-2222-2222": "CVE-2222-2222",
			"GHSA-3333-3333-3333": "",
			"GHSA-5555-5555-5555": "CVE-1111-1111",
		},
		ghsasByCVE: map[string][]string{
			"CVE-2222-2222": {"GHSA-2222-2222-2222"},
			"CVE-4444-4444": nil,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			// We'll use the memfs implementation so that our updates don't actually write
			// back to disk.
			fsys := memfs.New(os.DirFS("testdata/discover_aliases/advisories"))

			advisoryDocs, err := v2.NewIndex(context.Background(), fsys)
			if err != nil {
				t.Fatalf("unable to create advisory docs index: %v", err)
			}

			opts := DiscoverAliasesOptions{
				AdvisoryDocs:     advisoryDocs,
				AliasFinder:      mockAF,
				SelectedPackages: map[string]struct{}{tt.selectedPackage: {}},
			}

			err = DiscoverAliases(context.Background(), opts)

			if tt.wantErr != (err != nil) {
				t.Fatalf("DiscoverAliases() error = %v, wantErr %v", err, tt.wantErr)
			}

			// If we got an error, and we expected one, we're done.
			if err != nil {
				return
			}

			if diff := cmp.Diff(tt.expectedUpdatedDocument, advisoryDocs.Select().WhereName(tt.selectedPackage).Configurations()[0]); diff != "" {
				t.Errorf("DiscoverAliases() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

type mockAliasFinder struct {
	cveByGHSA  map[string]string
	ghsasByCVE map[string][]string
}

func (f *mockAliasFinder) CVEForGHSA(_ context.Context, ghsaID string) (string, error) {
	return f.cveByGHSA[ghsaID], nil
}

func (f *mockAliasFinder) GHSAsForCVE(_ context.Context, cveID string) ([]string, error) {
	return f.ghsasByCVE[cveID], nil
}
