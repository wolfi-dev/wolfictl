package apk

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_getApkPackages(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "APKINDEX.tar.gz"))
	assert.NoError(t, err)

	// create a test server for melange bump to fetch the tarball and generate SHA
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request parameters
		assert.Equal(t, req.URL.String(), "/APKINDEX.tar.gz")

		// Send response to be tested
		_, err = rw.Write(data)
		assert.NoError(t, err)
	}))

	c := New(server.Client(), server.URL+"/APKINDEX.tar.gz")
	wolfiPackages, err := c.GetApkPackages()
	assert.NoError(t, err)
	assert.Equal(t, "x86_64", wolfiPackages["pkgconf-doc"].Arch)
	assert.Equal(t, "5.2_rc4-r0", wolfiPackages["bash-doc"].Version)
}

func Test_ParseApkIndex(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "APKINDEX"))
	assert.NoError(t, err)

	wolfiPackages, err := ParseUnpackedApkIndex(f)
	assert.NoError(t, err)
	assert.Equal(t, "4.33-r0", wolfiPackages["libev-doc"].Version)
	assert.Equal(t, "0.19.0-r3", wolfiPackages["tini"].Version)
}
