package checks

import (
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiff(t *testing.T) {
	resultDir := t.TempDir()

	dir := filepath.Join("testdata", "diff")
	originalData, err := os.ReadFile(filepath.Join(dir, "test_orig.apk"))
	assert.NoError(t, err)

	apkIndexData, err := os.ReadFile(filepath.Join(dir, "APKINDEX.tgz"))
	assert.NoError(t, err)

	// create a test server to download the test apk from
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/APKINDEX.tar.gz":
			_, err = rw.Write(apkIndexData)
			assert.NoError(t, err)
		case "/test-1.2.3-r0.apk":
			_, err = rw.Write(originalData)
			assert.NoError(t, err)
		case "/test_sub-1.2.3-r0.apk":
			_, err = rw.Write(originalData)
			assert.NoError(t, err)
		default:
			http.Error(rw, "Not found", http.StatusNotFound)
		}
	}))

	diffOpts := DiffOptions{
		ApkIndexURL:         server.URL + "/APKINDEX.tar.gz",
		Client:              server.Client(),
		PackageListFilename: filepath.Join(dir, "packages.log"),
		Dir:                 resultDir,
		PackagesDir:         dir,
		Logger:              log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix),
	}
	err = diffOpts.Diff()
	assert.NoError(t, err)

	diffLogFile := filepath.Join(resultDir, "diff.log")

	actual, err := os.ReadFile(diffLogFile)
	assert.NoError(t, err)

	expected, err := os.ReadFile(filepath.Join(dir, "expected.txt"))
	assert.NoError(t, err)

	assert.Contains(t, string(actual), string(expected))
}
