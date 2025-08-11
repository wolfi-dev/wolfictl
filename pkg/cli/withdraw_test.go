package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReadPackagesFromFile(t *testing.T) {
	tests := []struct {
		name         string
		fileContent  string
		wantPackages []string
		wantErr      bool
	}{
		{
			name: "basic package list",
			fileContent: `package1-1.0.0-r0.apk
package2-2.0.0-r1.apk
package3-3.0.0-r2`,
			wantPackages: []string{"package1-1.0.0-r0.apk", "package2-2.0.0-r1.apk", "package3-3.0.0-r2"},
			wantErr:      false,
		},
		{
			name: "with comments and blank lines",
			fileContent: `# This is a comment
package1-1.0.0-r0.apk

# Another comment
package2-2.0.0-r1.apk

package3-3.0.0-r2`,
			wantPackages: []string{"package1-1.0.0-r0.apk", "package2-2.0.0-r1.apk", "package3-3.0.0-r2"},
			wantErr:      false,
		},
		{
			name: "with whitespace",
			fileContent: `  package1-1.0.0-r0.apk  
	package2-2.0.0-r1.apk	
   package3-3.0.0-r2   `,
			wantPackages: []string{"package1-1.0.0-r0.apk", "package2-2.0.0-r1.apk", "package3-3.0.0-r2"},
			wantErr:      false,
		},
		{
			name: "empty file",
			fileContent: `


# Only comments

`,
			wantPackages: []string{},
			wantErr:      false,
		},
		{
			name: "mixed content",
			fileContent: `# Withdraw these packages
package1-1.0.0-r0.apk
# This one too
package2-2.0.0-r1.apk

# Skip this line
package3-3.0.0-r2.apk
`,
			wantPackages: []string{"package1-1.0.0-r0.apk", "package2-2.0.0-r1.apk", "package3-3.0.0-r2.apk"},
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			tmpFile := filepath.Join(t.TempDir(), "packages.txt")
			if err := os.WriteFile(tmpFile, []byte(tt.fileContent), 0o644); err != nil {
				t.Fatal(err)
			}

			// Test the function
			gotPackages, err := readPackagesFromFile(tmpFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("readPackagesFromFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Handle comparison between nil and empty slice
			if len(gotPackages) == 0 && len(tt.wantPackages) == 0 {
				return // Both are effectively empty
			}
			if !reflect.DeepEqual(gotPackages, tt.wantPackages) {
				t.Errorf("readPackagesFromFile() = %v, want %v", gotPackages, tt.wantPackages)
			}
		})
	}
}

func TestReadPackagesFromFileNotFound(t *testing.T) {
	_, err := readPackagesFromFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("readPackagesFromFile() expected error for non-existent file, got nil")
	}
}
