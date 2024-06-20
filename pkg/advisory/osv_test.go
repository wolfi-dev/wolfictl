package advisory

import (
	"context"
	"os"
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func Test_BuildOSVDataset(t *testing.T) {
	const advisoriesDir = "./testdata/osv/advisories"
	const expectedOSVDir = "./testdata/osv/expected"

	advisoryFsys := rwos.DirFS(advisoriesDir)
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
