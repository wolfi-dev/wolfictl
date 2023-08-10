package advisory

import (
	"io"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func Test_ExportFuncs(t *testing.T) {
	const testdataDir = "./testdata/export/advisories"

	cases := []struct {
		name                string
		exportFuncUnderTest func(ExportOptions) (io.Reader, error)
		pathToExpectedData  string
	}{
		{
			name:                "csv",
			exportFuncUnderTest: ExportCSV,
			pathToExpectedData:  "./testdata/export/expected.csv",
		},
		{
			name:                "yaml",
			exportFuncUnderTest: ExportYAML,
			pathToExpectedData:  "./testdata/export/expected.yaml",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			advisoryFsys := rwos.DirFS(testdataDir)
			advisoryDocs, err := v2.NewIndex(advisoryFsys)
			require.NoError(t, err)
			indices := []*configs.Index[v2.Document]{advisoryDocs}

			opts := ExportOptions{
				AdvisoryDocIndices: indices,
			}

			exported, err := tt.exportFuncUnderTest(opts)
			assert.NoError(t, err)

			exportedBytes, err := io.ReadAll(exported)
			require.NoError(t, err)

			if p := tt.pathToExpectedData; p != "" {
				expectedBytes, err := os.ReadFile(p)
				require.NoError(t, err)

				if diff := cmp.Diff(string(expectedBytes), string(exportedBytes)); diff != "" {
					t.Errorf("ExportCSV() produced unexpected data (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestExportYAML(t *testing.T) {
	cases := []struct {
		name               string
		advisoryDirs       []string
		pathToExpectedData string
		errorAssertion     assert.ErrorAssertionFunc
	}{
		{
			name: "single advisories dir",
			advisoryDirs: []string{
				"./testdata/export/advisories",
			},
			pathToExpectedData: "./testdata/export/expected.yaml",
			errorAssertion:     assert.NoError,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			indices := make([]*configs.Index[v2.Document], 0, len(tt.advisoryDirs))
			for _, dir := range tt.advisoryDirs {
				advisoryFsys := rwos.DirFS(dir)
				advisoryDocs, err := v2.NewIndex(advisoryFsys)
				require.NoError(t, err)
				indices = append(indices, advisoryDocs)
			}

			opts := ExportOptions{
				AdvisoryDocIndices: indices,
			}

			exported, err := ExportYAML(opts)
			tt.errorAssertion(t, err)

			exportedBytes, err := io.ReadAll(exported)
			require.NoError(t, err)

			if p := tt.pathToExpectedData; p != "" {
				expectedBytes, err := os.ReadFile(p)
				require.NoError(t, err)

				if diff := cmp.Diff(string(expectedBytes), string(exportedBytes)); diff != "" {
					t.Errorf("ExportYAML() produced unexpected data (-want +got):\n%s", diff)
				}
			}
		})
	}
}
