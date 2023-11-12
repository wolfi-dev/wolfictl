package distro

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetect(t *testing.T) {
	// Create a test directory with a few git repos, some of which are distro-related

	tempDir, err := os.MkdirTemp("", "test-distro-detect-")
	require.NoError(t, err)
	t.Cleanup(func() {
		err := os.RemoveAll(tempDir)
		require.NoError(t, err)
	})

	repos := []struct {
		name       string
		remoteURLs []string
	}{
		{
			name: "my-wolfi",
			remoteURLs: []string{
				"https://github.com/wolfi-dev/os.git",
				"https://foo.git",
			},
		},
		{
			name: "some-other-repo",
			remoteURLs: []string{
				"https://some-other-repo.git",
			},
		},
		{
			name: "my-advisories",
			remoteURLs: []string{
				"git@github.com:wolfi-dev/advisories.git",
			},
		},
	}

	repoAbsolutePath := func(repoName string) string {
		return filepath.Join(tempDir, repoName)
	}

	for _, r := range repos {
		repoDir := repoAbsolutePath(r.name)
		err := os.Mkdir(repoDir, 0o755)
		require.NoError(t, err)

		_, err = git.PlainInit(repoDir, false)
		require.NoError(t, err)

		repo, err := git.PlainOpen(repoDir)
		require.NoError(t, err)

		_, err = repo.CreateRemote(&config.RemoteConfig{
			Name: "origin",
			URLs: r.remoteURLs,
		})
		require.NoError(t, err)

		// We need to create a commit so that HEAD exists.
		w, err := repo.Worktree()
		require.NoError(t, err)
		_, err = w.Commit("Initial commit", &git.CommitOptions{
			AllowEmptyCommits: true,
		})
		require.NoError(t, err)
	}

	originalWorkDir, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.Chdir(originalWorkDir) //nolint:errCheck
	})

	newWorkDir := repoAbsolutePath(repos[0].name)
	err = os.Chdir(newWorkDir)
	require.NoError(t, err)

	// Run the function under test

	d, err := Detect()
	require.NoError(t, err)

	// Check the results

	// (We need to resolve the symlinks because this test uses temp dirs, which are symlinked on some operating systems.)
	expectedDistroRepoDir, err := filepath.EvalSymlinks(repoAbsolutePath(repos[0].name))
	require.NoError(t, err)
	expectedAdvisoriesRepoDir, err := filepath.EvalSymlinks(repoAbsolutePath(repos[2].name))
	require.NoError(t, err)

	assert.Equal(t, "Wolfi", d.Absolute.Name)
	assert.Equal(t, expectedDistroRepoDir, d.Local.PackagesRepo.Dir)
	assert.Equal(t, expectedAdvisoriesRepoDir, d.Local.AdvisoriesRepo.Dir)
	assert.Equal(t, "https://packages.wolfi.dev/os", d.Absolute.APKRepositoryURL)
}
