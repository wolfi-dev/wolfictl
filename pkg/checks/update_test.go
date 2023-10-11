package checks

import (
	"bytes"
	"errors"
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
	yamlData := []byte("package:\n  name: cheese\n  version: 1\nupdate:\n  manual: true\n")
	fileContainsUpdate := filepath.Join(dir, "contains.yaml")
	err := os.WriteFile(fileContainsUpdate, yamlData, os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}

	o := CheckUpdateOptions{}

	checkErrors := make(lint.EvalRuleErrors, 0)
	// check update key exists
	o.validateUpdateConfig([]string{fileContainsUpdate}, &checkErrors)

	assert.Empty(t, checkErrors)

	// create a temporary file without an update key
	yamlData = []byte("package:\n  name: cheese\n  version: 1\n")
	fileNoContainsUpdate := filepath.Join(dir, "does_not_contain.yaml")
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(fileNoContainsUpdate, yamlData, os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}

	// check the update key does not exist
	o.validateUpdateConfig([]string{fileNoContainsUpdate}, &checkErrors)
	assert.NotEmpty(t, checkErrors)
}

func TestCheckUpdate(t *testing.T) {
	d, err := filepath.Abs("./testdata")
	assert.NoError(t, err)

	o := CheckUpdateOptions{
		Dir:    d,
		Logger: log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix),
	}

	tests := []struct {
		name    string
		file    string
		wantErr error
	}{
		{
			name:    "upstream repo has 'v' prefix in tag but manifest does not",
			file:    "git-checkout-wrong-tag.yaml",
			wantErr: errors.New("given tag '1.10.0' does not match upstream version 'v1.10.0'"),
		},
		{
			name:    "upstream repo has 'v' prefix in tag and also manifest does",
			file:    "git-checkout-correct-tag.yaml",
			wantErr: nil,
		},
		{
			name:    "upstream repo has 'v' prefix in tag but only tag prefix is set",
			file:    "git-checkout-wrong-no-strip.yaml",
			wantErr: errors.New("ref vv1.10.0: couldn't find remote ref \"refs/tags/vv1.10.0\""),
		},
		{
			name:    "upstream repo has 'v' prefix in tag but only strip prefix is set",
			file:    "git-checkout-wrong-just-strip.yaml",
			wantErr: errors.New("ref 1.10.0: couldn't find remote ref \"refs/tags/1.10.0\""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := o.CheckUpdates([]string{tt.file})
			if (err != nil) != (tt.wantErr != nil) {
				t.Fatalf("CheckUpdates() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				assert.Contains(t, err.Error(), tt.wantErr.Error())
			}
		})
	}
}
