package vuln

import "testing"

func TestValidateID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{
			name:    "valid CVE",
			id:      "CVE-2018-9999",
			wantErr: false,
		},
		{
			name:    "valid GHSA",
			id:      "GHSA-4qj9-c6q9-9j9q",
			wantErr: false,
		},
		{
			name:    "valid Go",
			id:      "GO-2018-9999",
			wantErr: false,
		},
		{
			name:    "invalid CVE",
			id:      "CVE-2018-999",
			wantErr: true,
		},
		{
			name:    "invalid GHSA",
			id:      "GHSA-4aj9-c6q9-9j91",
			wantErr: true,
		},
		{
			name:    "invalid Go",
			id:      "GO-2018-999",
			wantErr: true,
		},
		{
			name:    "empty",
			id:      "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateID(tt.id); (err != nil) != tt.wantErr {
				t.Errorf("ValidateID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
