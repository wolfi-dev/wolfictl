package checks

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-billy/v5/util"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/stretchr/testify/assert"

	"github.com/wolfi-dev/wolfictl/pkg/lint"

	"github.com/wolfi-dev/wolfictl/pkg/update"
)

func TestProcessUpdatesGitCheckout(t *testing.T) {
	checkErrors := make(lint.EvalRuleErrors, 0)

	newVersion := "9.8.7"

	// git dir will contain a test git repo that will be cloned to verify the check works
	gitDir := t.TempDir()

	// config dir will contain a modified test melange config
	configDir := t.TempDir()

	config, err := os.ReadFile(filepath.Join("testdata", "git-checkout.yaml"))
	assert.NoError(t, err)

	// create a local test repository that we can clone to verify the check works
	commit := createTestRepo(t, gitDir, newVersion)
	latestVersions := map[string]update.NewVersionResults{"git-checkout": {Version: newVersion, Commit: commit}}

	// replace the repository value with the local test repo we just created
	config = bytes.ReplaceAll(config, []byte("REPLACE_ME"), []byte(gitDir))
	err = os.WriteFile(filepath.Join(configDir, "git-checkout.yaml"), config, os.FileMode(0o644))
	assert.NoError(t, err)

	o := CheckUpdateOptions{
		Dir:    configDir,
		Logger: log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix),
	}

	err = o.processUpdates(latestVersions, &checkErrors)
	assert.NoError(t, err)
	assert.Len(t, checkErrors, 0)
}

func TestProcessUpdatesFetch(t *testing.T) {
	checkErrors := make(lint.EvalRuleErrors, 0)

	newVersion := "9.8.7"

	// config dir will contain a modified test melange config
	configDir := t.TempDir()

	config, err := os.ReadFile(filepath.Join("testdata", "fetch.yaml"))
	assert.NoError(t, err)

	// create a test server for melange bump to fetch the tarball and generate SHA
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request parameters
		assert.Equal(t, req.URL.String(), "/wine/cheese/cheese-v9.8.7.tar.gz")

		// Send response to be tested
		_, err = rw.Write([]byte("foo"))
		assert.NoError(t, err)
	}))

	latestVersions := map[string]update.NewVersionResults{"fetch": {Version: newVersion}}

	// replace the fetch URL value with the test server we just created
	config = bytes.ReplaceAll(config, []byte("REPLACE_ME"), []byte(server.URL))

	err = os.WriteFile(filepath.Join(configDir, "fetch.yaml"), config, os.FileMode(0o644))
	assert.NoError(t, err)

	o := CheckUpdateOptions{
		Dir:    configDir,
		Logger: log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix),
	}

	err = o.processUpdates(latestVersions, &checkErrors)
	assert.NoError(t, err)
	assert.Len(t, checkErrors, 0)
}

// create a test git repo and tag it with the version expected to be cloned in the check
func createTestRepo(t *testing.T, dir, tag string) string {
	fs := osfs.New(dir)

	storage := filesystem.NewStorage(fs, cache.NewObjectLRUDefault())
	wt, err := fs.Chroot("melange")
	assert.NoError(t, err)

	r, err := git.Init(storage, wt)
	assert.NoError(t, err)

	w, err := r.Worktree()
	assert.NoError(t, err)

	err = util.WriteFile(w.Filesystem, "cheese.txt", []byte("bar"), 0o644)
	assert.NoError(t, err)

	_, err = w.Add("cheese.txt")
	assert.NoError(t, err)

	sig := &object.Signature{
		Name:  "John Doe",
		Email: "john@doe.org",
		When:  time.Now(),
	}

	c, err := w.Commit("initial test checkin", &git.CommitOptions{
		Author: sig,
	})
	assert.NoError(t, err)

	tagOptions := &git.CreateTagOptions{
		Message: tag,
		Tagger:  sig,
	}

	_, err = r.CreateTag(tag, c, tagOptions)
	assert.NoError(t, err)

	return c.String()
}

func TestUpdateKeyExists(t *testing.T) {
	dir := t.TempDir()
	// create a temporary file with an update key
	yamlData := []byte("name: cheese\nupdate:\n  foo: true\n")
	fileContainsUpdate := filepath.Join(dir, "contains.yaml")
	err := os.WriteFile(fileContainsUpdate, yamlData, os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}

	checkErrors := make(lint.EvalRuleErrors, 0)
	// check update key exists
	validateUpdateConfig([]string{fileContainsUpdate}, &checkErrors)

	assert.Empty(t, checkErrors)

	// create a temporary file without an update key
	yamlData = []byte("name: cheese\n")
	fileNoContainsUpdate := filepath.Join(dir, "does_not_contain.yaml")
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(fileNoContainsUpdate, yamlData, os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}

	// check the update key does not exist
	validateUpdateConfig([]string{fileNoContainsUpdate}, &checkErrors)
	assert.NotEmpty(t, checkErrors)
}
