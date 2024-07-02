package update

import (
	"testing"

	"chainguard.dev/melange/pkg/config"
)

func TestGitLabMonitor_prepareLatestVersion(t *testing.T) {
	tests := []struct {
		name            string
		versionList     []VersionComit
		packageConfig   *config.Configuration
		expectedVersion string
		expectedCommit  string
		expectError     bool
	}{
		{
			name:          "empty version list",
			versionList:   []VersionComit{},
			packageConfig: &config.Configuration{},
			expectError:   true,
		},
		{
			name:        "version ignored by regex",
			versionList: []VersionComit{{Version: "v1.0.0-beta", Commit: "abc123"}},
			packageConfig: &config.Configuration{
				Update: config.Update{
					IgnoreRegexPatterns: []string{"beta"},
				},
			},
			expectError: true,
		},
		{
			name: "negative version ignored by regex",
			versionList: []VersionComit{
				{Version: "v1.0.0-beta", Commit: "abc123"},
				{Version: "v1.0.0", Commit: "def456"},
			},
			packageConfig: &config.Configuration{
				Update: config.Update{
					IgnoreRegexPatterns: []string{"beta"},
					GitLabMonitor:       &config.GitLabMonitor{},
				},
			},
			expectedVersion: "v1.0.0",
			expectedCommit:  "def456",
			expectError:     false,
		},
		{
			name:        "valid version found",
			versionList: []VersionComit{{Version: "v1.0.0", Commit: "def456"}},
			packageConfig: &config.Configuration{
				Update: config.Update{
					GitLabMonitor: &config.GitLabMonitor{},
				},
			},
			expectedVersion: "v1.0.0",
			expectedCommit:  "def456",
			expectError:     false,
		},
		{
			name: "multiple versions with proper latest picked",
			versionList: []VersionComit{
				{Version: "2.0.1-alpha", Commit: "ghi789"},
				{Version: "1.0.0", Commit: "def456"},
				{Version: "1.5.0", Commit: "jkl012"},
				{Version: "2.0.0", Commit: "mno345"},
			},
			packageConfig: &config.Configuration{
				Update: config.Update{
					IgnoreRegexPatterns: []string{"alpha"}, // Ignoring alpha versions
					GitLabMonitor:       &config.GitLabMonitor{},
				},
			},
			expectedVersion: "2.0.0",
			expectedCommit:  "mno345",
			expectError:     false,
		},
		{
			name: "multiple versions with proper latest picked and prefix stripped",
			versionList: []VersionComit{
				{Version: "v2.0.0-alpha", Commit: "ghi789"},
				{Version: "v1.0.0", Commit: "def456"},
				{Version: "v1.5.0", Commit: "jkl012"},
			},
			packageConfig: &config.Configuration{
				Update: config.Update{
					IgnoreRegexPatterns: []string{"alpha"}, // Ignoring alpha versions
					GitLabMonitor: &config.GitLabMonitor{
						StripPrefix: "v",
					},
				},
			},
			expectedVersion: "1.5.0",
			expectedCommit:  "jkl012",
			expectError:     false,
		},
		{
			name: "multiple versions with proper latest picked and suffix stripped",
			versionList: []VersionComit{
				{Version: "1.0.0-rs", Commit: "def456"},
				{Version: "2.0.0-rs", Commit: "ghi789"},
				{Version: "1.5.0-rs", Commit: "jkl012"},
			},
			packageConfig: &config.Configuration{
				Update: config.Update{
					IgnoreRegexPatterns: []string{"alpha"}, // Ignoring alpha versions
					GitLabMonitor: &config.GitLabMonitor{
						StripSuffix: "-rs",
					},
				},
			},
			expectedVersion: "2.0.0",
			expectedCommit:  "ghi789",
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, commit, err := prepareLatestVersion(tt.versionList, tt.packageConfig)
			if (err != nil) != tt.expectError {
				t.Errorf("prepareLatestVersion() error = %v, expectError %v", err, tt.expectError)
				return
			}
			if version != tt.expectedVersion {
				t.Errorf("Expected version %v, got %v", tt.expectedVersion, version)
			}
			if commit != tt.expectedCommit {
				t.Errorf("Expected commit %v, got %v", tt.expectedCommit, commit)
			}
		})
	}
}
