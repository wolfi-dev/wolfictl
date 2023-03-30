package git

import (
	"testing"
	"time"

	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-billy/v5/util"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/stretchr/testify/assert"
)

func TestGetCurrentVersionFromTag(t *testing.T) {
	t.Setenv("GIT_AUTHOR_NAME", "test")
	t.Setenv("GIT_AUTHOR_EMAIL", "test@tester.com")
	tests := []struct {
		existing []string
		expected string
		err      bool
	}{
		{existing: nil, expected: "", err: true},
		{existing: []string{"v1.2.3", "v1.2.3.1"}, expected: "v1.2.3.1"},
		{existing: []string{"v1.2", "v1.2+1"}, expected: "v1.2+1"},
		{existing: []string{"v1.2.4", "v1.2.4-1"}, expected: "v1.2.4"},
	}
	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			dir := t.TempDir()
			setupTestRepo(t, dir)

			for _, tag := range test.existing {
				err := CreateTag(dir, tag)
				assert.NoError(t, err)
			}

			current, err := GetVersionFromTag(dir, 1)
			assert.Equal(t, test.err, err != nil)

			if !test.err {
				assert.Equal(t, test.expected, current.Original())
			}
		})
	}
}

func setupTestRepo(t *testing.T, dir string) *git.Repository {
	fs := osfs.New(dir)

	storage := filesystem.NewStorage(fs, cache.NewObjectLRUDefault())
	wt, err := fs.Chroot("test")
	assert.NoError(t, err)

	r, err := git.Init(storage, wt)
	assert.NoError(t, err)

	w, err := r.Worktree()
	assert.NoError(t, err)

	err = util.WriteFile(w.Filesystem, "foo.yaml", []byte("ok"), 0o644)
	assert.NoError(t, err)

	_, err = w.Add("foo.yaml")
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
