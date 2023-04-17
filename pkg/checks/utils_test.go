package checks

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChecks_ParsePackages(t *testing.T) {
	dir := t.TempDir()

	// packages.log is an example output of packages that were built by melange, eg wolfi/os
	data, err := os.ReadFile(filepath.Join("testdata", "packages.log"))
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	// if a top level melange package was built then it's subpackages will also have been built
	melangeData, err := os.ReadFile(filepath.Join("testdata", "subpackages_melange.yaml"))
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	err = os.WriteFile(filepath.Join(dir, "bind.yaml"), melangeData, os.ModePerm)
	assert.NoError(t, err)

	packages, err := getNewPackages(filepath.Join("testdata", "packages.log"))
	assert.NoError(t, err)

	assert.Equal(t, "3.7.8", packages["gnutls-c++"].Version)
	assert.Equal(t, "1.2.3", packages["bind-doc"].Version)
	assert.Equal(t, "1.2.3", packages["bind-dev"].Version)
	assert.Equal(t, "1.2.3", packages["grape-utils"].Version)

	// if-conditional subpackages might not be built
	_, ok := packages["foo-utils"]
	assert.False(t, ok, "foo-utils should not be present")
}

func TestChecks_downloadCurrentAPK(t *testing.T) {
	dir := t.TempDir()

	data, err := os.ReadFile(filepath.Join("testdata", "hello-wolfi-2.12-r1.apk"))
	assert.NoError(t, err)

	// create a test server to download the test apk from
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request parameters
		assert.Equal(t, req.URL.String(), "/hello-wolfi-2.12-r1.apk")

		// Send response to be tested
		_, err = rw.Write(data)
		assert.NoError(t, err)
	}))

	err = downloadCurrentAPK(server.Client(), server.URL+"/APKINDEX.tar.gz", "hello-wolfi-2.12-r1.apk", dir)
	assert.NoError(t, err)

	data, err = os.ReadFile(filepath.Join(dir, "usr", "bin", "hello"))
	assert.NoError(t, err)

	assert.NotEmpty(t, data)
}
