package update

import (
	"testing"

	"chainguard.dev/melange/pkg/config"

	"github.com/stretchr/testify/assert"
)

func TestOptions_transformVersion(t *testing.T) {
	tests := []struct {
		name         string
		updateConfig config.Update
		version      string
		expected     string
		expectError  bool
	}{
		{
			name:         "No transformation",
			updateConfig: config.Update{},
			version:      "1.2.3",
			expected:     "1.2.3",
			expectError:  false,
		},
		{
			name: "Single transformation",
			updateConfig: config.Update{
				VersionTransform: []config.VersionTransform{
					{Match: "_", Replace: "."},
				},
			},
			version:     "1_2_3",
			expected:    "1.2.3",
			expectError: false,
		},
		{
			name: "Multiple transformations",
			updateConfig: config.Update{
				VersionTransform: []config.VersionTransform{
					{Match: "_", Replace: "."},
					{Match: "^v", Replace: ""},
				},
			},
			version:     "v1_2_3",
			expected:    "1.2.3",
			expectError: false,
		},
		{
			name: "Invalid regex pattern",
			updateConfig: config.Update{
				VersionTransform: []config.VersionTransform{
					{Match: "[", Replace: "."},
				},
			},
			version:     "1[2[3",
			expected:    "",
			expectError: true,
		},
		{
			name: "Multiple Complex Tranformations",
			updateConfig: config.Update{
				VersionTransform: []config.VersionTransform{
					{Match: `(\d+)_(\d+)_(.*?)$`, Replace: "${1}.${2}_${3}"},
					{Match: "P", Replace: "p"},
				},
			},
			version:     "9_7_P1",
			expected:    "9.7_p1",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := transformVersion(tt.updateConfig, tt.version)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
