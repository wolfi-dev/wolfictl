package v2

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/chainguard-dev/yam/pkg/yam/formatted"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/go-version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestDocument_Validate(t *testing.T) {
	testTime := Timestamp(time.Date(2022, 9, 26, 0, 0, 0, 0, time.UTC))
	testValidAdvisory := Advisory{
		ID: "CVE-2020-0001",
		Events: []Event{
			{
				Timestamp: testTime,
				Type:      EventTypeDetection,
				Data:      Detection{Type: DetectionTypeManual},
			},
		},
	}

	tests := []struct {
		name    string
		doc     Document
		wantErr bool
	}{
		{
			name: "valid",
			doc: Document{
				SchemaVersion: SchemaVersion,
				Package: Package{
					Name: "good-package",
				},
				Advisories: Advisories{testValidAdvisory},
			},
			wantErr: false,
		},
		{
			name: "schema is newer",
			doc: Document{
				SchemaVersion: newerSchemaVersion(SchemaVersion),
				Package: Package{
					Name: "good-package",
				},
				Advisories: Advisories{testValidAdvisory},
			},
			wantErr: true,
		},
		{
			name: "schema too old",
			doc: Document{
				SchemaVersion: "1.0.0",
				Package: Package{
					Name: "good-package",
				},
				Advisories: Advisories{testValidAdvisory},
			},
			wantErr: true,
		},
		{
			name: "missing package name",
			doc: Document{
				SchemaVersion: SchemaVersion,
				Package:       Package{},
				Advisories:    Advisories{testValidAdvisory},
			},
			wantErr: true,
		},
		{
			name: "no advisories",
			doc: Document{
				SchemaVersion: SchemaVersion,
				Package: Package{
					Name: "good-package",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.doc.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func newerSchemaVersion(currentSchemaVersion string) string {
	v, _ := version.NewVersion(currentSchemaVersion) //nolint:errcheck

	segments := v.Segments()
	if len(segments) <= 1 {
		return fmt.Sprintf("%s.1", currentSchemaVersion)
	}

	return fmt.Sprintf("%d.%d", segments[0], segments[1]+1)
}

func TestDocument_full_coverage(t *testing.T) {
	testTime := Timestamp(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))

	testDocument := Document{
		SchemaVersion: SchemaVersion,
		Package: Package{
			Name: "full",
		},
		Advisories: Advisories{
			{
				ID: "CVE-2000-0001",
				Aliases: []string{
					"GHSA-xxxx-xxxx-xxx9",
					"GO-2000-0001",
				},
				Events: []Event{
					{
						Timestamp: testTime,
						Type:      EventTypeDetection,
						Data: Detection{
							Type: DetectionTypeManual,
						},
					},
					{
						Timestamp: testTime,
						Type:      EventTypeDetection,
						Data: Detection{
							Type: DetectionTypeNVDAPI,
							Data: DetectionNVDAPI{
								CPESearched: "cpe:2.3:a:*:tinyxml:*:*:*:*:*:*:*:*",
								CPEFound:    "cpe:2.3:a:tinyxml_project:tinyxml:*:*:*:*:*:*:*:*",
							},
						},
					},
					{
						Timestamp: testTime,
						Type:      EventTypeTruePositiveDetermination,
						Data: TruePositiveDetermination{
							Note: "Something something true positive.",
						},
					},
					{
						Timestamp: testTime,
						Type:      EventTypeFalsePositiveDetermination,
						Data: FalsePositiveDetermination{
							Type: FPTypeVulnerabilityRecordAnalysisContested,
							Note: "Something something false positive.",
						},
					},
					{
						Timestamp: testTime,
						Type:      EventTypeFalsePositiveDetermination,
						Data: FalsePositiveDetermination{
							Type: FPTypeComponentVulnerabilityMismatch,
							Note: "Something something false positive.",
						},
					},
					{
						Timestamp: testTime,
						Type:      EventTypeFalsePositiveDetermination,
						Data: FalsePositiveDetermination{
							Type: FPTypeVulnerableCodeVersionNotUsed,
							Note: "Something something false positive.",
						},
					},
					{
						Timestamp: testTime,
						Type:      EventTypeFalsePositiveDetermination,
						Data: FalsePositiveDetermination{
							Type: FPTypeVulnerableCodeNotIncludedInPackage,
							Note: "Something something false positive.",
						},
					},
					{
						Timestamp: testTime,
						Type:      EventTypeFalsePositiveDetermination,
						Data: FalsePositiveDetermination{
							Type: FPTypeVulnerableCodeNotInExecutionPath,
							Note: "Something something false positive.",
						},
					},
					{
						Timestamp: testTime,
						Type:      EventTypeFalsePositiveDetermination,
						Data: FalsePositiveDetermination{
							Type: FPTypeVulnerableCodeCannotBeControlledByAdversary,
							Note: "Something something false positive.",
						},
					},
					{
						Timestamp: testTime,
						Type:      EventTypeFalsePositiveDetermination,
						Data: FalsePositiveDetermination{
							Type: FPTypeInlineMitigationsExist,
							Note: "Something something false positive.",
						},
					},
					{
						Timestamp: testTime,
						Type:      EventTypeFixed,
						Data: Fixed{
							FixedVersion: "1.2.3-r4",
						},
					},
					{
						Timestamp: testTime,
						Type:      EventTypeAnalysisNotPlanned,
						Data: AnalysisNotPlanned{
							Note: "Something something analysis not planned.",
						},
					},
					{
						Timestamp: testTime,
						Type:      EventTypeFixNotPlanned,
						Data: FixNotPlanned{
							Note: "Something something fix not planned.",
						},
					},
				},
			},
		},
	}

	f, err := os.Open("testdata/full.advisories.yaml")
	require.NoError(t, err)

	t.Run("decode", func(t *testing.T) {
		expected := testDocument

		actual, err := decodeDocument(f)
		require.NoError(t, err)

		if diff := cmp.Diff(expected, *actual); diff != "" {
			t.Errorf("unexpected document (-want +got):\n%s", diff)
			t.FailNow()
		}

		t.Run("document should be valid", func(t *testing.T) {
			err := actual.Validate()
			assert.NoError(t, err)
		})
	})

	// Reset seek position to prepare for reading in next test.
	_, err = f.Seek(0, io.SeekStart)
	require.NoError(t, err)

	t.Run("encode", func(t *testing.T) {
		actual := new(bytes.Buffer)

		encoder, err := formatted.NewEncoder(actual).UseOptions(formatted.EncodeOptions{
			Indent:         2,
			GapExpressions: []string{"."},
		})
		require.NoError(t, err)

		node := &yaml.Node{} // TODO: this can be simplified when yam supports encoding an empty interface
		err = node.Encode(testDocument)
		require.NoError(t, err)
		err = encoder.Encode(node)
		require.NoError(t, err)

		expectedBytes, err := io.ReadAll(f)
		require.NoError(t, err)

		if diff := cmp.Diff(string(expectedBytes), actual.String()); diff != "" {
			t.Errorf("unexpected document (-want +got):\n%s", diff)
		}
	})
}
