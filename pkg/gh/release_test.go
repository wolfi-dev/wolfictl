package gh

import (
	"log"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5/util"

	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/filesystem"

	"github.com/hashicorp/go-version"
	"github.com/stretchr/testify/assert"
)

func TestPrereleaseBump(t *testing.T) {
	tests := []struct {
		current  string
		expected string
		ReleaseOptions
	}{
		{
			current: "v1", expected: "v1.0.1ab1",
			ReleaseOptions: ReleaseOptions{
				BumpPrereleaseWithPrefix: "ab",
			},
		},
		{
			current: "v1.2", expected: "v1.2.1ab1",
			ReleaseOptions: ReleaseOptions{
				BumpPrereleaseWithPrefix: "ab",
			},
		},
		{
			current: "v1.2.3", expected: "v1.2.4ab1",
			ReleaseOptions: ReleaseOptions{
				BumpPrereleaseWithPrefix: "ab",
			},
		},
		{
			current: "v1.2.4ab1", expected: "v1.2.4ab2",
			ReleaseOptions: ReleaseOptions{
				BumpPrereleaseWithPrefix: "ab",
			},
		},
		{
			current: "v1.2.4ab10", expected: "v1.2.4ab11",
			ReleaseOptions: ReleaseOptions{
				BumpPrereleaseWithPrefix: "ab",
			},
		},
		{
			current: "v1.2.4ab12", expected: "v1.2.4ab13",
			ReleaseOptions: ReleaseOptions{
				BumpPrereleaseWithPrefix: "ab",
			},
		},
		{
			current: "v0.0.0", expected: "v0.0.1ab1",
			ReleaseOptions: ReleaseOptions{
				BumpPrereleaseWithPrefix: "ab",
			},
		},
		{
			current: "v1.0.0", expected: "v2.0.0",
			ReleaseOptions: ReleaseOptions{
				BumpMajor: true,
			},
		},
		{
			current: "v1.1.0", expected: "v1.2.0",
			ReleaseOptions: ReleaseOptions{
				BumpMinor: true,
			},
		},
		{
			current: "v1.0.1", expected: "v1.0.2",
			ReleaseOptions: ReleaseOptions{
				BumpPatch: true,
			},
		},
		{
			current: "v1.0.1", expected: "v1.0.2ab1",
			ReleaseOptions: ReleaseOptions{
				BumpPatch:                true,
				BumpPrereleaseWithPrefix: "ab",
			},
		},
		{
			current: "v1.0.10ab10", expected: "v1.0.10ab11",
			ReleaseOptions: ReleaseOptions{
				BumpPrereleaseWithPrefix: "ab",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.current, func(t *testing.T) {
			c, err := version.NewVersion(test.current)
			assert.NoError(t, err)
			e, err := version.NewVersion(test.expected)
			assert.NoError(t, err)

			got, err := test.ReleaseOptions.bumpReleaseVersion(c)
			assert.NoError(t, err)

			assert.Equal(t, e.Original(), got.Original())
		})
	}
}

func TestGetCurrentVersionFromTag(t *testing.T) {
	o := ReleaseOptions{
		Logger: log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix),
	}

	tests := []struct {
		existing []string
		expected string
	}{
		{existing: nil, expected: "v0.0.0"},
		{existing: []string{"v1.2.3ab1", "v1.2.3ab2"}, expected: "v1.2.3ab2"},
		{existing: []string{"v1.2.3ab2", "v1.2.3ab1"}, expected: "v1.2.3ab2"},
		{existing: []string{"v1.2.4cg9", "v1.2.4cg10"}, expected: "v1.2.4cg10"},
		{existing: []string{"v1.2.4cg10", "v1.2.4cg9"}, expected: "v1.2.4cg10"},
	}
	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			dir := t.TempDir()
			setupTestRepo(t, dir)

			o.Dir = dir

			for _, tag := range test.existing {
				err := o.createTag(tag, "test", "test@tester.com")
				assert.NoError(t, err)
			}

			current, err := o.getCurrentVersionFromTag()
			assert.NoError(t, err)

			assert.Equal(t, test.expected, current.Original())
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
