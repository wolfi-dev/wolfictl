package v2

import "testing"

func TestFalsePositiveDetermination_Validate(t *testing.T) {
	tests := []struct {
		name    string
		fp      FalsePositiveDetermination
		wantErr bool
	}{
		{
			name: "valid",
			fp: FalsePositiveDetermination{
				Type: "vulnerable-code-version-not-used",
			},
			wantErr: false,
		},
		{
			name: "unknown type",
			fp: FalsePositiveDetermination{
				Type: "invalid",
			},
			wantErr: true,
		},
		{
			name: "empty type",
			fp: FalsePositiveDetermination{
				Type: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fp.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("FalsePositiveDetermination.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
