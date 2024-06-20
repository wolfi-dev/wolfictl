package advisory

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

var update = flag.Bool("update", false, "update golden files instead of comparing them to actual output")

func Test_BuildOSVDataset(t *testing.T) {
	const advisoriesDir = "./testdata/osv/advisories"
	const expectedOSVDir = "./testdata/osv/expected"

	advisoryFsys := rwos.DirFS(advisoriesDir)
	advisoryDocs, err := v2.NewIndex(context.Background(), advisoryFsys)
	require.NoError(t, err)
	indices := []*configs.Index[v2.Document]{advisoryDocs}

	var outputDir string
	if *update {
		outputDir = expectedOSVDir
	} else {
		tempDir, err := os.MkdirTemp("", "test-osv")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		outputDir = tempDir
	}

	opts := OSVOptions{
		AdvisoryDocIndices: indices,
		OutputDirectory:    outputDir,
		Ecosystem:          "wolfi",
	}

	err = BuildOSVDataset(context.Background(), opts)
	require.NoError(t, err)

	if *update {
		// We've updated the golden files as requested, and there's nothing to compare/test.
		return
	}

	expectedOSVFiles, err := os.ReadDir(expectedOSVDir)
	require.NoError(t, err)

	actualOSVFiles, err := os.ReadDir(outputDir)
	require.NoError(t, err)

	if len(expectedOSVFiles) != len(actualOSVFiles) {
		t.Fatal("missing OSV files")
	}

	for i, expectedCVEFile := range expectedOSVFiles {
		expectedBytes, err := os.ReadFile(filepath.Join(expectedOSVDir, expectedCVEFile.Name()))
		require.NoError(t, err)

		actualBytes, err := os.ReadFile(filepath.Join(outputDir, actualOSVFiles[i].Name()))
		require.NoError(t, err)

		if diff := cmp.Diff(string(expectedBytes), string(actualBytes)); diff != "" {
			t.Errorf("BuildOSVDataset() produced unexpected data (-want +got):\n%s", diff)
		}
	}
}
