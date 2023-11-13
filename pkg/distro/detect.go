package distro

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"golang.org/x/exp/slices"
)

// Detect tries to automatically detect which distro the user wants to
// operate on, and the corresponding directory paths for the distro and
// advisories repos.
func Detect() (Distro, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return Distro{}, err
	}

	distro, err := identifyDistroFromLocalRepoDir(cwd)
	if err != nil {
		return Distro{}, err
	}

	// We assume that the parent directory of the initially found repo directory is
	// a directory that contains all the relevant repo directories.
	dirOfRepos := filepath.Dir(cwd)

	// We either have a distro (packages) repo or an advisories repo, but not both.
	// Now we need to find the other one.

	switch {
	case distro.Local.DistroRepoDir == "":
		distroDir, err := findDistroDir(distro.Absolute, dirOfRepos)
		if err != nil {
			return Distro{}, err
		}
		distro.Local.DistroRepoDir = distroDir
		return distro, nil

	case distro.Local.AdvisoriesRepoDir == "":
		advisoryDir, err := findAdvisoriesDir(distro.Absolute, dirOfRepos)
		if err != nil {
			return Distro{}, err
		}
		distro.Local.AdvisoriesRepoDir = advisoryDir
		return distro, nil
	}

	return Distro{}, fmt.Errorf("unable to detect distro")
}

var errNotDistroRepo = fmt.Errorf("current directory is not a distro (packages) or advisories repository")

func identifyDistroFromLocalRepoDir(dir string) (Distro, error) {
	repo, err := git.PlainOpen(dir)
	if err != nil {
		return Distro{}, fmt.Errorf("unable to identify distro: couldn't open git repo: %w", err)
	}

	config, err := repo.Config()
	if err != nil {
		return Distro{}, err
	}

	for _, remoteConfig := range config.Remotes {
		urls := remoteConfig.URLs
		if len(urls) == 0 {
			continue
		}

		url := urls[0]

		for _, d := range []AbsoluteProperties{wolfiDistro, chainguardDistro} {
			if slices.Contains(d.DistroRemoteURLs, url) {
				return Distro{
					Absolute: d,
					Local: LocalProperties{
						DistroRepoDir:     dir,
						AdvisoriesRepoDir: "", // This gets filled in later outside of this function.
					},
				}, nil
			}

			if slices.Contains(d.AdvisoriesRemoteURLs, url) {
				return Distro{
					Absolute: d,
					Local: LocalProperties{
						DistroRepoDir:     "", // This gets filled in later outside of this function.
						AdvisoriesRepoDir: dir,
					},
				}, nil
			}
		}
	}

	return Distro{}, errNotDistroRepo
}

// findDistroDir returns the local filesystem path to the directory for the
// distro (packages) repo for the given targetDistro, by examining the child
// directories within dirOfRepos.
func findDistroDir(targetDistro AbsoluteProperties, dirOfRepos string) (string, error) {
	return findRepoDir(targetDistro, dirOfRepos, func(d Distro) string {
		return d.Local.DistroRepoDir
	})
}

// findAdvisoriesDir returns the local filesystem path to the directory for the
// advisories repo for the given targetDistro, by examining the child
// directories within dirOfRepos.
func findAdvisoriesDir(targetDistro AbsoluteProperties, dirOfRepos string) (string, error) {
	return findRepoDir(targetDistro, dirOfRepos, func(d Distro) string {
		return d.Local.AdvisoriesRepoDir
	})
}

// findRepoDir looks for a repo directory (for either a distro/package repo or
// an advisories repo) in the given directory of repos that matches the given
// distro. It uses the given function to extract the repo directory from a
// Distro.
func findRepoDir(targetDistro AbsoluteProperties, dirOfRepos string, getRepoDir func(Distro) string) (string, error) {
	files, err := os.ReadDir(dirOfRepos)
	if err != nil {
		return "", err
	}

	for _, f := range files {
		if !f.IsDir() {
			continue
		}

		d, err := identifyDistroFromLocalRepoDir(filepath.Join(dirOfRepos, f.Name()))
		if err != nil {
			// no usable distro or advisories repo here
			continue
		}
		if d.Absolute.Name != targetDistro.Name {
			// This is not the distro you're looking for... 👋
			continue
		}

		dir := getRepoDir(d)
		if dir == "" {
			continue
		}

		return dir, nil
	}

	return "", fmt.Errorf("unable to find repo dir")
}
