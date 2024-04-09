package distro

import (
	"fmt"
	"os"
	"slices"

	"github.com/go-git/go-git/v5"
)

// DetectV2 tries to detect which distro the user wants to operate on by seeing
// if the current working directory is the distro's packages repo. No
// advisory-related repositories are detected.
func DetectV2() (Distro, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return Distro{}, err
	}

	d, err := DetectFromDirV2(cwd)
	if err != nil {
		return Distro{}, err
	}

	return d, nil
}

// DetectFromDirV2 tries to identify a Distro by inspecting the given directory
// to see if it is a repository for a distro's packages.
func DetectFromDirV2(dir string) (Distro, error) {
	distro, err := identifyDistroFromLocalPackagesRepoDir(dir)
	if err != nil {
		return Distro{}, err
	}

	forkPoint, err := findRepoForkPoint(distro.Local.PackagesRepo.Dir, distro.Local.PackagesRepo.UpstreamName)
	if err != nil {
		return Distro{}, err
	}
	distro.Local.PackagesRepo.ForkPoint = forkPoint

	return distro, nil
}

var ErrNotPackagesRepo = fmt.Errorf("directory is not a distro (packages) repository")

func identifyDistroFromLocalPackagesRepoDir(dir string) (Distro, error) {
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
		}
	}

	return Distro{}, ErrNotPackagesRepo
}
