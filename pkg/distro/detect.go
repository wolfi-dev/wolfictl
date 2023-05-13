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
func Detect() (DetectedDistro, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return DetectedDistro{}, err
	}

	distro, err := detectDistroInRepo(cwd)
	if err != nil {
		return DetectedDistro{}, err
	}

	d, err := getDistroByName(distro.Name)
	if err != nil {
		return DetectedDistro{}, err
	}

	// We assume that the parent directory of the initially found repo directory is
	// a directory that contains all the relevant repo directories.
	dirOfRepos := filepath.Dir(cwd)

	switch {
	case distro.DistroRepoDir == "":
		distroDir, err := findDistroDir(d, dirOfRepos)
		if err != nil {
			return DetectedDistro{}, err
		}
		distro.DistroRepoDir = distroDir
		return distro, nil

	case distro.AdvisoriesRepoDir == "":
		advisoryDir, err := findAdvisoriesDir(d, dirOfRepos)
		if err != nil {
			return DetectedDistro{}, err
		}
		distro.AdvisoriesRepoDir = advisoryDir
		return distro, nil
	}

	return DetectedDistro{}, fmt.Errorf("unable to detect distro")
}

var errNotDistroRepo = fmt.Errorf("current directory is not a distro or advisories repository")

func detectDistroInRepo(dir string) (DetectedDistro, error) {
	repo, err := git.PlainOpen(dir)
	if err != nil {
		return DetectedDistro{}, fmt.Errorf("unable to identify distro: couldn't open git repo: %w", err)
	}

	config, err := repo.Config()
	if err != nil {
		return DetectedDistro{}, err
	}

	for _, remoteConfig := range config.Remotes {
		urls := remoteConfig.URLs
		if len(urls) == 0 {
			continue
		}

		url := urls[0]

		for _, d := range []identifiableDistro{wolfiDistro, chainguardDistro} {
			if slices.Contains(d.distroRemoteURLs, url) {
				return DetectedDistro{
					Name:          d.name,
					DistroRepoDir: dir,
				}, nil
			}

			if slices.Contains(d.advisoriesRemoteURLs, url) {
				return DetectedDistro{
					Name:              d.name,
					AdvisoriesRepoDir: dir,
				}, nil
			}
		}
	}

	return DetectedDistro{}, errNotDistroRepo
}

func getDistroByName(name string) (identifiableDistro, error) {
	for _, d := range []identifiableDistro{wolfiDistro, chainguardDistro} {
		if d.name == name {
			return d, nil
		}
	}

	return identifiableDistro{}, fmt.Errorf("unknown distro: %s", name)
}

func findDistroDir(targetDistro identifiableDistro, dirOfRepos string) (string, error) {
	return findRepoDir(targetDistro, dirOfRepos, func(d DetectedDistro) string {
		return d.DistroRepoDir
	})
}

func findAdvisoriesDir(targetDistro identifiableDistro, dirOfRepos string) (string, error) {
	return findRepoDir(targetDistro, dirOfRepos, func(d DetectedDistro) string {
		return d.AdvisoriesRepoDir
	})
}

func findRepoDir(targetDistro identifiableDistro, dirOfRepos string, getRepoDir func(DetectedDistro) string) (string, error) {
	files, err := os.ReadDir(dirOfRepos)
	if err != nil {
		return "", err
	}

	for _, f := range files {
		if !f.IsDir() {
			continue
		}

		d, err := detectDistroInRepo(filepath.Join(dirOfRepos, f.Name()))
		if err != nil {
			// no usable distro or advisories repo here
			continue
		}

		if d.Name != targetDistro.name {
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

type identifiableDistro struct {
	name                                   string
	distroRemoteURLs, advisoriesRemoteURLs []string
}

var (
	wolfiDistro = identifiableDistro{
		name: "Wolfi",
		distroRemoteURLs: []string{
			"git@github.com:wolfi-dev/os.git",
			"https://github.com/wolfi-dev/os.git",
		},
		advisoriesRemoteURLs: []string{
			"git@github.com:wolfi-dev/advisories.git",
			"https://github.com/wolfi-dev/advisories.git",
		},
	}

	chainguardDistro = identifiableDistro{
		name: "Chainguard",
		distroRemoteURLs: []string{
			"git@github.com:chainguard-dev/enterprise-packages.git",
			"https://github.com/chainguard-dev/enterprise-packages.git",
		},
		advisoriesRemoteURLs: []string{
			"git@github.com:chainguard-dev/enterprise-advisories.git",
			"https://github.com/chainguard-dev/enterprise-advisories.git",
		},
	}
)

type DetectedDistro struct {
	Name              string
	DistroRepoDir     string
	AdvisoriesRepoDir string
}
