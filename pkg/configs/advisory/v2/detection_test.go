package v2

import "testing"

func TestDetection_Validate(t *testing.T) {
	tests := []struct {
		name      string
		detection Detection
		wantErr   bool
	}{
		{
			name: "manual",
			detection: Detection{
				Type: DetectionTypeManual,
			},
			wantErr: false,
		},
		{
			name: "nvdapi",
			detection: Detection{
				Type: DetectionTypeNVDAPI,
				Data: DetectionNVDAPI{
					CPESearched: "cpe:2.3:a:*:tinyxml:*:*:*:*:*:*:*:*",
					CPEFound:    "cpe:2.3:a:tinyxml_project:tinyxml:*:*:*:*:*:*:*:*",
				},
			},
			wantErr: false,
		},
		{
			name: "nvdapi missing CPE data",
			detection: Detection{
				Type: DetectionTypeNVDAPI,
				Data: DetectionNVDAPI{
					CPESearched: "",
					CPEFound:    "cpe:2.3:a:tinyxml_project:tinyxml:*:*:*:*:*:*:*:*",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid type",
			detection: Detection{
				Type: "foo",
			},
			wantErr: true,
		},
		{
			name: "no type",
			detection: Detection{
				Type: "",
			},
			wantErr: true,
		},
		{
			name: "mismatched type and data",
			detection: Detection{
				Type: DetectionTypeManual,
				Data: DetectionNVDAPI{
					CPESearched: "cpe:2.3:a:*:tinyxml:*:*:*:*:*:*:*:*",
					CPEFound:    "cpe:2.3:a:tinyxml_project:tinyxml:*:*:*:*:*:*:*:*",
				},
			},
			wantErr: true,
		},
		{
			name: "scan/v1",
			detection: Detection{
				Type: DetectionTypeScanV1,
				Data: DetectionScanV1{
					SubpackageName:    "crane-docs",
					ComponentID:       "fe8053a3adedc5d0",
					ComponentName:     "github.com/docker/distribution",
					ComponentVersion:  "v2.8.1+incompatible",
					ComponentType:     "go-module",
					ComponentLocation: "/usr/bin/crane",
					Scanner:           "grype",
				},
			},
			wantErr: false,
		},
		{
			name: "scan/v1 missing required fields",
			detection: Detection{
				Type: DetectionTypeScanV1,
				Data: DetectionScanV1{
					SubpackageName:    "",
					ComponentID:       "fe8053a3adedc5d0",
					ComponentName:     "github.com/docker/distribution",
					ComponentVersion:  "",
					ComponentType:     "go-module",
					ComponentLocation: "",
					Scanner:           "",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.detection.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
