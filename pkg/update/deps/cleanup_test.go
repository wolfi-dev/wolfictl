package deps

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	melangebuild "chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/config"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"github.com/wolfi-dev/wolfictl/pkg/yam"
	"gopkg.in/yaml.v3"
)

func TestCleanupDeps(t *testing.T) {
	testcases := []struct {
		name        string
		filename    string
		expectedErr bool
	}{{
		name:     "update existing go/bump",
		filename: "config-1",
	}, {
		name:     "add go/bump",
		filename: "config-2",
	}, {
		name:     "add go/bump before go mod tidy",
		filename: "config-3",
	}, {
		name:     "cleanup gobump, empty deps",
		filename: "config-4",
	}, {
		name:     "cleanup gobump, empty replaces",
		filename: "config-5",
	}, {
		name:     "cleanup gobump and update another go/bump",
		filename: "config-6",
	}, {
		name:     "go.mod require and replace conflicting to different version of the same grpc version",
		filename: "config-7",
	}, {
		name:     "upgrade gorm version in replaces with a newer version in go.mod in a replace block",
		filename: "config-8",
	}, {
		name:     "multiple gobump blocks deleted",
		filename: "config-10",
	}}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			dir := "testdata"
			tempDir := t.TempDir()
			filename := fmt.Sprintf("%s.yaml", tc.filename)

			copyFile(t, filepath.Join(dir, filename), tempDir)
			copyFile(t, filepath.Join(dir, ".yam.yaml"), tempDir)

			yamlContent, err := os.ReadFile(filepath.Join(tempDir, filename))
			require.NoError(t, err)

			expectedYAMLContent, err := os.ReadFile(filepath.Join(dir, tc.filename+"_expected.yaml"))
			require.NoError(t, err)

			// now make sure update config is configured
			updated, err := config.ParseConfiguration(context.Background(), filepath.Join(dir, filename))
			require.NoError(t, err)

			pctx := &melangebuild.PipelineBuild{
				Build: &melangebuild.Build{
					Configuration: *updated,
				},
				Package: &updated.Package,
			}

			// get a map of variable mutations we can substitute vars in URLs
			mutations, err := melangebuild.MutateWith(pctx, map[string]string{})
			require.NoError(t, err)

			var doc yaml.Node
			err = yaml.Unmarshal(yamlContent, &doc)
			require.NoError(t, err)

			err = CleanupGoBumpDeps(&doc, updated, false, mutations)
			if tc.expectedErr && err == nil {
				t.Errorf("expected error")
			} else if err != nil && !tc.expectedErr {
				t.Fatal(err)
			}
			modifiedYAML, err := yaml.Marshal(&doc)
			require.NoError(t, err)

			if err := os.WriteFile(filepath.Join(tempDir, filename), modifiedYAML, 0o600); err != nil {
				t.Errorf("failed to write file: %v", err)
			}

			err = yam.FormatConfigurationFile(tempDir, filename)
			require.NoError(t, err)

			modifiedYAMLContent, err := os.ReadFile(filepath.Join(tempDir, filename))
			require.NoError(t, err)

			if diff := cmp.Diff(string(modifiedYAMLContent), string(expectedYAMLContent)); diff != "" {
				t.Errorf("unexpected file modification results (-want, +got):\n%s GOT: %s\n", diff, string(modifiedYAMLContent))
			}
		})
	}
}
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	_, err := exec.Command("cp", "-r", src, dst).Output()
	if err != nil {
		t.Fatal(err)
	}
}

func TestContainsGoBump(t *testing.T) {
	t.Skip()
	testcases := []struct {
		name           string
		filename       string
		containsGoBump bool
	}{{
		name:           "update existing go/bump",
		filename:       "config-1",
		containsGoBump: true,
	}, {
		name:           "add go/bump",
		filename:       "config-2",
		containsGoBump: true,
	}, {
		name:           "add go/bump before go mod tidy",
		filename:       "config-3",
		containsGoBump: true,
	}, {
		name:           "cleanup gobump, empty deps",
		filename:       "config-4",
		containsGoBump: true,
	}, {
		name:           "cleanup gobump, empty replaces",
		filename:       "config-5",
		containsGoBump: true,
	}, {
		name:           "cleanup gobump and update another go/bump",
		filename:       "config-6",
		containsGoBump: true,
	}, {
		name:           "go.mod require and replace conflicting to different version of the same grpc version",
		filename:       "config-7",
		containsGoBump: true,
	}, {
		name:           "upgrade gorm version in replaces with a newer version in go.mod in a replace block",
		filename:       "config-8",
		containsGoBump: true,
	}, {
		name:           "no go/bump in the pipelines",
		filename:       "config-9",
		containsGoBump: false,
	}}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			dir := "testdata"
			filename := fmt.Sprintf("%s.yaml", tc.filename)

			// now make sure update config is configured
			updated, err := config.ParseConfiguration(context.Background(), filepath.Join(dir, filename))
			require.NoError(t, err)
			exists := ContainsGoBumpPipeline(updated)
			if tc.containsGoBump != exists {
				t.Errorf("unexpected value for contains go/bump: got %v and expected %v", exists, tc.containsGoBump)
			}
		})
	}
}
