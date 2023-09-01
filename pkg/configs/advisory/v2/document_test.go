package v2

import (
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/go-version"
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
