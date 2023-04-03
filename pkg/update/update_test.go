package update

import (
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wolfi-dev/wolfictl/pkg/melange"

	"chainguard.dev/melange/pkg/build"

	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-billy/v5/util"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"gopkg.in/yaml.v3"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// a bit more than a typical unit test but is useful to test a git branch with melange bump
func TestMonitorService_updatePackagesGitRepository(t *testing.T) {
	dir := t.TempDir()

	data, err := os.ReadFile(filepath.Join("testdata", "cheese-1.5.10.tar.gz"))
	assert.NoError(t, err)

	// create a test server for melange bump to fetch the tarball and generate SHA
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request parameters
		assert.Equal(t, req.URL.String(), "/wine/cheese/cheese-1.5.10.tar.gz")

		// Send response to be tested
		_, err = rw.Write(data)
		assert.NoError(t, err)
	}))

	r := setupTestWolfiRepo(t, dir, server.URL)

	o := Options{
		DryRun:        true,
		Logger:        log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix),
		DefaultBranch: "master",
	}

	o.PackageConfigs, err = melange.ReadAllPackagesFromRepo(filepath.Join(dir, "melange"))
	assert.NoError(t, err)

	// fake a new version available
	newVersion := map[string]NewVersionResults{"cheese": {Version: "1.5.10"}}
	errorMessages := make(map[string]string)
	err = o.updatePackagesGitRepository(r, newVersion)
	assert.NoError(t, err)
	assert.Empty(t, errorMessages)

	// assert the results
	rsData, err := os.ReadFile(filepath.Join(dir, "melange", "cheese.yaml"))
	assert.NoError(t, err)

	rsMelangeConfig := &build.Configuration{}
	err = yaml.Unmarshal(rsData, rsMelangeConfig)
	assert.NoError(t, err)

	assert.Equal(t, "1.5.10", rsMelangeConfig.Package.Version)
	assert.Equal(t, "cc2c52929ace57623ff517408a577e783e10042655963b2c8f0633e109337d7a", rsMelangeConfig.Pipeline[0].With["expected-sha256"])
}

func setupTestWolfiRepo(t *testing.T, dir, testURL string) *git.Repository {
	fs := osfs.New(dir)
	data, err := os.ReadFile(filepath.Join("testdata", "cheese.yaml"))
	assert.NoError(t, err)

	// replace the URL melange bump uses to fetch the tarball from
	melangConfig := strings.Replace(string(data), "REPLACE_ME", testURL, 1)

	storage := filesystem.NewStorage(fs, cache.NewObjectLRUDefault())
	wt, err := fs.Chroot("melange")
	assert.NoError(t, err)

	r, err := git.Init(storage, wt)
	assert.NoError(t, err)

	w, err := r.Worktree()
	assert.NoError(t, err)

	err = util.WriteFile(w.Filesystem, "cheese.yaml", []byte(melangConfig), 0o644)
	assert.NoError(t, err)

	_, err = w.Add("cheese.yaml")
	assert.NoError(t, err)

	_, err = w.Commit("initial test checkin", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "John Doe",
			Email: "john@doe.org",
			When:  time.Now(),
		},
	})
	assert.NoError(t, err)

	return r
}

// a bit more than a typical unit test but is useful to test a git branch with melange bump
func TestUpdate_updateMakefile(t *testing.T) {
	tempDir := t.TempDir()
	data, err := os.ReadFile(filepath.Join("testdata", "Makefile"))
	assert.NoError(t, err)

	// make the temp test dir a git repo
	fs := osfs.New(tempDir)
	storage := filesystem.NewStorage(fs, cache.NewObjectLRUDefault())
	wt, err := fs.Chroot("melange")
	require.NoError(t, err)
	r, err := git.Init(storage, wt)
	assert.NoError(t, err)
	w, err := r.Worktree()
	require.NoError(t, err)

	// copy test file into temp git repo
	err = util.WriteFile(w.Filesystem, "Makefile", data, 0o644)
	assert.NoError(t, err)

	o := Options{
		Logger: log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix),
	}
	err = o.updateMakefile(filepath.Join(tempDir, "melange"), "zlib", "1.3.0", w)
	assert.NoError(t, err)

	// assert the Makefile contains the correct changes
	resultData, err := os.ReadFile(filepath.Join(tempDir, "melange", "Makefile"))
	assert.NoError(t, err)
	assert.Contains(t, string(resultData), "build-package,zlib,1.3.0-r0)")
}
