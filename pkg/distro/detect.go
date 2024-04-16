package distro

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	wgit "github.com/wolfi-dev/wolfictl/pkg/git"
	"golang.org/x/exp/slices"
)

// Detect tries to automatically detect which distro the user wants to operate
// on by trying to match the current working directory with a known repository
// for a distro's packages or advisories.
func Detect() (Distro, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return Distro{}, err
	}

	d, err := DetectFromDir(cwd)
	if err != nil {
		return Distro{}, err
	}

	return d, nil
}

// DetectFromDir tries to identify a Distro by inspecting the given directory to
// see if it is a repository for a distro's packages or advisories.
func DetectFromDir(dir string) (Distro, error) {
	distro, err := identifyDistroFromLocalRepoDir(dir)
	if err != nil {
		return Distro{}, err
	}

	// We assume that the parent directory of the initially found repo directory is
	// a directory that contains all the relevant repo directories.
	dirOfRepos := filepath.Dir(dir)

	// We either have a distro (packages) repo or an advisories repo, but not both.
	// Now we need to find the other one.

	switch {
	case distro.Local.PackagesRepo.Dir == "":
		distroDir, err := findDistroDir(distro.Absolute, dirOfRepos)
		if err != nil {
			return Distro{}, fmt.Errorf("unable to find distro (packages) dir: %w", err)
		}
		distro.Local.PackagesRepo.Dir = distroDir
		d, err := identifyDistroFromLocalRepoDir(distroDir)
		if err != nil {
			return Distro{}, err
		}
		distro.Local.PackagesRepo.UpstreamName = d.Local.PackagesRepo.UpstreamName
		forkPoint, err := findRepoForkPoint(distroDir, d.Local.PackagesRepo.UpstreamName)
		if err != nil {
			return Distro{}, err
		}
		distro.Local.PackagesRepo.ForkPoint = forkPoint

		// We also still need to get the advisories repo fork point.
		fp, err := findRepoForkPoint(distro.Local.AdvisoriesRepo.Dir, distro.Local.AdvisoriesRepo.UpstreamName)
		if err != nil {
			return Distro{}, err
		}
		distro.Local.AdvisoriesRepo.ForkPoint = fp
		return distro, nil

	case distro.Local.AdvisoriesRepo.Dir == "":
		advisoryDir, err := findAdvisoriesDir(distro.Absolute, dirOfRepos)
		if err != nil {
			return Distro{}, fmt.Errorf("unable to find advisories dir: %w", err)
		}
		distro.Local.AdvisoriesRepo.Dir = advisoryDir
		d, err := identifyDistroFromLocalRepoDir(advisoryDir)
		if err != nil {
			return Distro{}, err
		}
		distro.Local.AdvisoriesRepo.UpstreamName = d.Local.AdvisoriesRepo.UpstreamName
		forkPoint, err := findRepoForkPoint(advisoryDir, d.Local.AdvisoriesRepo.UpstreamName)
		if err != nil {
			return Distro{}, err
		}
		distro.Local.AdvisoriesRepo.ForkPoint = forkPoint

		// We also still need to get the distro (packages) repo fork point.
		fp, err := findRepoForkPoint(distro.Local.PackagesRepo.Dir, distro.Local.PackagesRepo.UpstreamName)
		if err != nil {
			return Distro{}, err
		}
		distro.Local.PackagesRepo.ForkPoint = fp
		return distro, nil
	}

	return Distro{}, fmt.Errorf("unable to detect distro")
}

var ErrNotDistroRepo = fmt.Errorf("directory is not a distro (packages) or advisories repository")

func identifyDistroFromLocalRepoDir(dir string) (Distro, error) {
	repo, err := git.PlainOpen(dir)
	if err != nil {
		return Distro{}, fmt.Errorf("unable to identify distro: couldn't open git repo: %v: %w", err, ErrNotDistroRepo)
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

		for _, d := range []AbsoluteProperties{wolfiDistro, chainguardDistro, extraPackagesDistro} {
			// Fill in the local properties that we can cheaply here. We'll fill in the rest
			// later, outside of this function call.

			if slices.Contains(d.DistroRemoteURLs(), url) {
				return Distro{
					Absolute: d,
					Local: LocalProperties{
						PackagesRepo: LocalRepo{
							Dir:          dir,
							UpstreamName: remoteConfig.Name,
							ForkPoint:    "", // This is slightly expensive to compute, so we do it later and only once per repo.
						},
					},
				}, nil
			}

			if slices.Contains(d.AdvisoriesRemoteURLs(), url) {
				return Distro{
					Absolute: d,
					Local: LocalProperties{
						AdvisoriesRepo: LocalRepo{
							Dir:          dir,
							UpstreamName: remoteConfig.Name,
							ForkPoint:    "", // This is slightly expensive to compute, so we do it later and only once per repo.
						},
					},
				}, nil
			}
		}
	}

	return Distro{}, ErrNotDistroRepo
}

func findRepoForkPoint(repoDir, remoteName string) (string, error) {
	repo, err := git.PlainOpen(repoDir)
	if err != nil {
		return "", fmt.Errorf("unable to find fork point for remote %q: %w", remoteName, err)
	}

	remote, err := repo.Remote(remoteName)
	if err != nil {
		return "", fmt.Errorf("unable to find fork point for remote %q: %w", remoteName, err)
	}

	head, err := repo.Head()
	if err != nil {
		return "", fmt.Errorf("unable to find fork point for remote %q: %w", remoteName, err)
	}

	upstreamRefName := fmt.Sprintf("refs/remotes/%s/main", remote.Config().Name)
	upstreamRef, err := repo.Reference(plumbing.ReferenceName(upstreamRefName), true)
	if err != nil {
		return "", fmt.Errorf("unable to get upstream ref %q: %w", upstreamRefName, err)
	}
	forkPoint, err := wgit.FindForkPoint(repo, head, upstreamRef)
	if err != nil {
		return "", fmt.Errorf("unable to find fork point for remote %q: %w", remoteName, err)
	}

	return forkPoint.String(), nil
}

// findDistroDir returns the local filesystem path to the directory for the
// distro (packages) repo for the given targetDistro, by examining the child
// directories within dirOfRepos.
func findDistroDir(targetDistro AbsoluteProperties, dirOfRepos string) (string, error) {
	return findRepoDir(targetDistro, dirOfRepos, func(d Distro) string {
		return d.Local.PackagesRepo.Dir
	})
}

// findAdvisoriesDir returns the local filesystem path to the directory for the
// advisories repo for the given targetDistro, by examining the child
// directories within dirOfRepos.
func findAdvisoriesDir(targetDistro AbsoluteProperties, dirOfRepos string) (string, error) {
	return findRepoDir(targetDistro, dirOfRepos, func(d Distro) string {
		return d.Local.AdvisoriesRepo.Dir
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
