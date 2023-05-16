package distro

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"golang.org/x/exp/slices"
)

// Distro represents a wolfictl-compatible distro, along with important
// properties discovered about how the user interacts with the distro.
type Distro struct {
	// Name of the distro.
	Name string

	// DistroRepoDir is the path to the directory containing the user's clone of the
	// distro repo, i.e. the repo containing the distro's build configurations.
	DistroRepoDir string

	// AdvisoriesRepoDir is the path to the directory containing the user's clone of
	// the advisories repo, i.e. the repo containing the distro's advisory data.
	AdvisoriesRepoDir string

	// APKRepositoryURL is the URL to the distro's package repository (e.g.
	// "https://packages.wolfi.dev/os").
	APKRepositoryURL string
}

// Detect tries to automatically detect which distro the user wants to
// operate on, and the corresponding directory paths for the distro and
// advisories repos.
func Detect() (Distro, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return Distro{}, err
	}

	distro, err := detectDistroInRepo(cwd)
	if err != nil {
		return Distro{}, err
	}

	d, err := getDistroByName(distro.Name)
	if err != nil {
		return Distro{}, err
	}

	// We assume that the parent directory of the initially found repo directory is
	// a directory that contains all the relevant repo directories.
	dirOfRepos := filepath.Dir(cwd)

	switch {
	case distro.DistroRepoDir == "":
		distroDir, err := findDistroDir(d, dirOfRepos)
		if err != nil {
			return Distro{}, err
		}
		distro.DistroRepoDir = distroDir
		return distro, nil

	case distro.AdvisoriesRepoDir == "":
		advisoryDir, err := findAdvisoriesDir(d, dirOfRepos)
		if err != nil {
			return Distro{}, err
		}
		distro.AdvisoriesRepoDir = advisoryDir
		return distro, nil
	}

	return Distro{}, fmt.Errorf("unable to detect distro")
}

var errNotDistroRepo = fmt.Errorf("current directory is not a distro or advisories repository")

func detectDistroInRepo(dir string) (Distro, error) {
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

		for _, d := range []identifiableDistro{wolfiDistro, chainguardDistro} {
			if slices.Contains(d.distroRemoteURLs, url) {
				return Distro{
					Name:             d.name,
					DistroRepoDir:    dir,
					APKRepositoryURL: d.apkRepositoryURL,
				}, nil
			}

			if slices.Contains(d.advisoriesRemoteURLs, url) {
				return Distro{
					Name:              d.name,
					AdvisoriesRepoDir: dir,
					APKRepositoryURL:  d.apkRepositoryURL,
				}, nil
			}
		}
	}

	return Distro{}, errNotDistroRepo
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
	return findRepoDir(targetDistro, dirOfRepos, func(d Distro) string {
		return d.DistroRepoDir
	})
}

func findAdvisoriesDir(targetDistro identifiableDistro, dirOfRepos string) (string, error) {
	return findRepoDir(targetDistro, dirOfRepos, func(d Distro) string {
		return d.AdvisoriesRepoDir
	})
}

func findRepoDir(targetDistro identifiableDistro, dirOfRepos string, getRepoDir func(Distro) string) (string, error) {
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
	apkRepositoryURL                       string
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
		apkRepositoryURL: "https://packages.wolfi.dev/os",
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
		apkRepositoryURL: "https://packages.cgr.dev/os",
	}
)
