package v2

import (
	"testing"
	"time"
)

func TestAdvisory_Validate(t *testing.T) {
	testTime := Timestamp(time.Date(2022, 9, 26, 0, 0, 0, 0, time.UTC))

	tests := []struct {
		name    string
		adv     Advisory
		wantErr bool
	}{
		{
			name: "valid",
			adv: Advisory{
				ID: "CVE-2020-0001",
				Events: []Event{
					{
						Timestamp: testTime,
						Type:      EventTypeDetection,
						Data: Detection{
							Type: DetectionTypeManual,
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid with aliases",
			adv: Advisory{
				ID: "CVE-2020-0001",
				Aliases: []string{
					"GHSA-5j9q-4xjw-3j3q",
					"GO-2023-0001",
				},
				Events: []Event{
					{
						Timestamp: testTime,
						Type:      EventTypeDetection,
						Data: Detection{
							Type: DetectionTypeManual,
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid ID",
			adv: Advisory{
				ID: "vulnerability",
				Events: []Event{
					{
						Timestamp: testTime,
						Type:      EventTypeDetection,
						Data: Detection{
							Type: DetectionTypeManual,
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid alias",
			adv: Advisory{
				ID: "CVE-2020-0001",
				Aliases: []string{
					"DSA-12345678",
				},
				Events: []Event{
					{
						Timestamp: testTime,
						Type:      EventTypeDetection,
						Data: Detection{
							Type: DetectionTypeManual,
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "duplicate aliases",
			adv: Advisory{
				ID: "CVE-2020-0001",
				Aliases: []string{
					"GHSA-5j9q-4xjw-3j3q",
					"GHSA-5j9q-4xjw-3j3q",
				},
				Events: []Event{
					{
						Timestamp: testTime,
						Type:      EventTypeDetection,
						Data: Detection{
							Type: DetectionTypeManual,
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "alias duplicates advisory ID",
			adv: Advisory{
				ID: "GHSA-5j9q-4xjw-3j3q",
				Aliases: []string{
					"GHSA-5j9q-4xjw-3j3q",
				},
				Events: []Event{
					{
						Timestamp: testTime,
						Type:      EventTypeDetection,
						Data: Detection{
							Type: DetectionTypeManual,
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "CVE in alias instead of advisory ID",
			adv: Advisory{
				ID: "GHSA-5j9q-4xjw-3j3q",
				Aliases: []string{
					"CVE-2020-0001",
				},
				Events: []Event{
					{
						Timestamp: testTime,
						Type:      EventTypeDetection,
						Data: Detection{
							Type: DetectionTypeManual,
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "no events",
			adv: Advisory{
				ID:     "CVE-2020-0001",
				Events: []Event{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.adv.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Advisory.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
