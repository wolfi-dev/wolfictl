package v2

import (
	"testing"
	"time"
)

func TestEvent_Validate(t *testing.T) {
	testTime := Timestamp(time.Date(2022, 9, 26, 0, 0, 0, 0, time.UTC))

	tests := []struct {
		name    string
		event   Event
		wantErr bool
	}{
		{
			name: "valid",
			event: Event{
				Timestamp: testTime,
				Type:      EventTypeDetection,
				Data: Detection{
					Type: DetectionTypeManual,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid timestamp",
			event: Event{
				Timestamp: Timestamp{},
				Type:      EventTypeTruePositiveDetermination,
				Data: TruePositiveDetermination{
					Note: "this is a note",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid type",
			event: Event{
				Timestamp: testTime,
				Type:      "foo",
			},
			wantErr: true,
		},
		{
			name: "no type",
			event: Event{
				Timestamp: testTime,
				Data:      AnalysisNotPlanned{},
			},
			wantErr: true,
		},
		{
			name: "invalid data for type",
			event: Event{
				Timestamp: testTime,
				Type:      EventTypeFixed,
				Data: Detection{
					Type: DetectionTypeManual,
				},
			},
			wantErr: true,
		},
		{
			name: "timestamp in the future",
			event: Event{
				Timestamp: Timestamp(time.Now().Add(24 * time.Hour)),
				Type:      EventTypeDetection,
				Data: Detection{
					Type: DetectionTypeManual,
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.event.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
