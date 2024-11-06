package checks

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/clog/slogtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wolfi-dev/wolfictl/pkg/apk"
)

func TestDiff(t *testing.T) {
	ctx := slogtest.Context(t)
	resultDir := t.TempDir()

	dir := filepath.Join("testdata", "diff")
	originalData, err := os.ReadFile(filepath.Join(dir, "test_orig.apk"))
	require.NoError(t, err)

	apkIndexData, err := os.ReadFile(filepath.Join(dir, "APKINDEX.tgz"))
	require.NoError(t, err)

	// create a test server to download the test apk from
	const apkindexEndpoint = "/APKINDEX.tar.gz"
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case apkindexEndpoint:
			_, err = rw.Write(apkIndexData)
			require.NoError(t, err)
		case "/test-1.2.3-r0.apk":
			_, err = rw.Write(originalData)
			require.NoError(t, err)
		case "/test_sub-1.2.3-r0.apk":
			_, err = rw.Write(originalData)
			require.NoError(t, err)
		default:
			http.Error(rw, "Not found", http.StatusNotFound)
		}
	}))

	newPackages, err := GetNewPackages(filepath.Join(dir, "packages.log"))
	require.NoError(t, err)

	diffOpts := DiffOptions{
		ApkIndexURL: server.URL + apkindexEndpoint,
		Client:      server.Client(),
		Dir:         resultDir,
		PackagesDir: dir,
	}

	apkContext := apk.New(diffOpts.Client, diffOpts.ApkIndexURL)
	existingPackages, err := apkContext.GetApkPackages()
	assert.NoError(t, err)

	err = diffOpts.Diff(ctx, existingPackages, newPackages)
	require.NoError(t, err)

	diffLogFile := filepath.Join(resultDir, "diff.log")

	actual, err := os.ReadFile(diffLogFile)
	require.NoError(t, err)

	expectedPackage := `
Package test:
Added: /test/wine.txt
Modified: /test/tester.txt
Deleted: /test/cheese.txt
`

	expectedSubpackage := `
Package test_sub:
Unchanged
`
	assert.Contains(t, string(actual), expectedPackage)
	assert.Contains(t, string(actual), expectedSubpackage)
}
