package vuln

import "testing"

func TestValidateCPE(t *testing.T) {
	tests := []struct {
		name    string
		cpe     string
		wantErr bool
	}{
		{
			name:    "valid URI",
			cpe:     "cpe:/a:microsoft:internet_explorer:8.0.6001:beta",
			wantErr: false,
		},
		{
			name:    "valid formatted string",
			cpe:     "cpe:2.3:a:*:tinyxml:6.0:*:*:*:*:*:*:*",
			wantErr: false,
		},
		{
			name:    "invalid",
			cpe:     "cpe::2.3:a:*:oversizedxml*:*:*:*:*:*:*",
			wantErr: true,
		},
		{
			name:    "empty",
			cpe:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateCPE(tt.cpe); (err != nil) != tt.wantErr {
				t.Errorf("ValidateCPE() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
