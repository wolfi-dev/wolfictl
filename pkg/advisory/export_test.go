package advisory

import (
	"context"
	"io"
	"os"
	"path"
	"strings"
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
			advisoryDocs, err := v2.NewIndex(context.Background(), advisoryFsys)
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
					t.Errorf("Export%s() produced unexpected data (-want +got):\n%s", strings.ToUpper(tt.name), diff)
				}
			}
		})
	}
}

func Test_BuildOSVDataset(t *testing.T) {
	const testdataDir = "./testdata/export/advisories"
	const expectedOSVDir = "./testdata/export/osv"

	advisoryFsys := rwos.DirFS(testdataDir)
	advisoryDocs, err := v2.NewIndex(context.Background(), advisoryFsys)
	require.NoError(t, err)
	indices := []*configs.Index[v2.Document]{advisoryDocs}

	tempOSVDir, err := os.MkdirTemp("", "test-osv")
	assert.NoError(t, err)
	defer os.RemoveAll(tempOSVDir)

	opts := OSVOptions{
		AdvisoryDocIndices: indices,
		OutputDirectory:    tempOSVDir,
		Ecosystem:          "wolfi",
	}

	err = BuildOSVDataset(context.Background(), opts)
	assert.NoError(t, err)

	expectedOSVFiles, err := os.ReadDir(expectedOSVDir)
	assert.NoError(t, err)

	actualOSVFiles, err := os.ReadDir(tempOSVDir)
	assert.NoError(t, err)

	if len(expectedOSVFiles) != len(actualOSVFiles) {
		t.Error("missing OSV files")
	}

	for i, expectedCVEFile := range expectedOSVFiles {
		expectedBytes, err := os.ReadFile(path.Join(expectedOSVDir, expectedCVEFile.Name()))
		require.NoError(t, err)

		actualBytes, err := os.ReadFile(path.Join(tempOSVDir, actualOSVFiles[i].Name()))
		require.NoError(t, err)

		if diff := cmp.Diff(string(expectedBytes), string(actualBytes)); diff != "" {
			t.Errorf("BuildOSVDataset() produced unexpected data (-want +got):\n%s", diff)
		}
	}
}
