package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestBumpEpoch(t *testing.T) {
	ctx := context.Background()

	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test")
	if err != nil {
		t.Fatalf("Error creating temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a temporary config file with a known epoch
	configFilePath := filepath.Join(tmpDir, "test_config.yaml")
	configContent := `
package:
  name: clickhouse
  version: 24.2.1.2248
  epoch: 6
`
	err = os.WriteFile(configFilePath, []byte(configContent), 0o600)
	if err != nil {
		t.Fatalf("Error creating temp config file: %v", err)
	}

	tests := []struct {
		desc            string
		increment       bool
		expectedEpoch   int
		expectedMessage string
	}{
		{
			desc:          "Incrementing epoch",
			increment:     true,
			expectedEpoch: 7,
			expectedMessage: "bumping clickhouse-24.2.1.2248-0 in " + configFilePath +
				" to epoch 7\n",
		},
		{
			desc:          "Decrementing epoch",
			increment:     false,
			expectedEpoch: 6,
			expectedMessage: "bumping clickhouse-24.2.1.2248-0 in " + configFilePath +
				" to epoch 6\n",
		},
		{
			desc:          "Decrementing epoch",
			increment:     false,
			expectedEpoch: 5,
			expectedMessage: "bumping clickhouse-24.2.1.2248-0 in " + configFilePath +
				" to epoch 5\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			opts := bumpOptions{
				repoDir:   tmpDir,
				dryRun:    false,
				increment: tc.increment,
			}

			// Test bumping epoch
			err := bumpEpoch(ctx, opts, configFilePath)
			if err != nil {
				t.Fatalf("Error bumping epoch: %v", err)
			}

			// Read the modified config file to check if the epoch is bumped
			modifiedConfigData, err := os.ReadFile(configFilePath)
			if err != nil {
				t.Fatalf("Error reading modified config file: %v", err)
			}

			var modifiedConfig map[string]interface{}
			err = yaml.Unmarshal(modifiedConfigData, &modifiedConfig)
			if err != nil {
				t.Fatalf("Error unmarshalling modified config: %v", err)
			}

			actualEpoch, ok := modifiedConfig["package"].(map[string]interface{})["epoch"].(int)
			if !ok {
				t.Fatalf("Error retrieving actual epoch from modified config")
			}

			if actualEpoch != tc.expectedEpoch {
				t.Errorf("Epoch not bumped correctly. Expected: %d, Got: %d", tc.expectedEpoch, actualEpoch)
			}
		})
	}
}
