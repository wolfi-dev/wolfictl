package advisory

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"chainguard.dev/melange/pkg/config"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/configs/build"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

var update = flag.Bool("update", false, "update golden files instead of comparing them to actual output")

func Test_BuildOSVDataset(t *testing.T) {
	const testdataOSVDir = "./testdata/osv"
	expectedOSVDir := filepath.Join(testdataOSVDir, "expected")

	advisoryRepos := []string{"advisories-repo-a", "advisories-repo-b"}
	var advisoryIndices []*configs.Index[v2.Document]
	for _, r := range advisoryRepos {
		fsys := rwos.DirFS(filepath.Join(testdataOSVDir, r))
		index, err := v2.NewIndex(context.Background(), fsys)
		require.NoError(t, err)
		advisoryIndices = append(advisoryIndices, index)
	}

	packageRepos := []string{"packages-repo-a", "packages-repo-b"}
	var packageIndices []*configs.Index[config.Configuration]
	for _, r := range packageRepos {
		fsys := rwos.DirFS(filepath.Join(testdataOSVDir, r))
		index, err := build.NewIndex(context.Background(), fsys)
		require.NoError(t, err)
		packageIndices = append(packageIndices, index)
	}

	// "repo-a" represents "wolfi" (both its packages and its advisories).
	addedEcosystems := []string{"Wolfi", ""}

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
		AdvisoryDocIndices:   advisoryIndices,
		PackageConfigIndices: packageIndices,
		AddedEcosystems:      addedEcosystems,
		OutputDirectory:      outputDir,
	}

	err := BuildOSVDataset(context.Background(), opts)
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
