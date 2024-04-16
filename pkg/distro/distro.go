package distro

import (
	"fmt"
)

// Distro represents a wolfictl-compatible distro, along with important
// properties discovered about how the user interacts with the distro.
type Distro struct {
	Local    LocalProperties
	Absolute AbsoluteProperties
}

// LocalProperties describe the aspects of the distro that are specific to the
// context of the user's local environment.
type LocalProperties struct {
	// PackagesRepo is the context about the user's local clone of the distro's
	// packages repo.
	PackagesRepo LocalRepo

	// AdvisoriesRepo is the context about the user's local clone of the distro's
	// advisories repo.
	AdvisoriesRepo LocalRepo
}

// LocalRepo stores the context about a local git repository that is needed for
// interacting with this distro.
type LocalRepo struct {
	// Dir is the path to the directory containing the user's clone of the repo.
	Dir string

	// UpstreamName is the name of the locally configured git remote that the
	// user's clone of the repo uses to reference the upstream repo.
	UpstreamName string

	// ForkPoint is the commit hash of the latest commit had in common between the
	// local repo and the upstream repo main branch.
	ForkPoint string
}

// AbsoluteProperties describe the aspects of the distro that are constant and
// not a function of any user's local environment.
type AbsoluteProperties struct {
	// The Name of the distro, e.g. "Wolfi".
	Name string

	// DistroRepoOwner is the GitHub organization name that owns the packages repo.
	DistroRepoOwner string

	// DistroPackagesRepo is the name of the distro's packages repo.
	DistroPackagesRepo string

	// DistroAdvisoriesRepo is the name of the distro's advisories repo.
	DistroAdvisoriesRepo string

	// APKRepositoryURL is the URL to the distro's package repository (e.g.
	// "https://packages.wolfi.dev/os").
	APKRepositoryURL string

	// SupportedArchitectures is a list of architectures supported by the distro.
	SupportedArchitectures []string
}

const (
	githubURLFormatGit   = "git@github.com:%s/%s"
	githubURLFormatHTTPS = "https://github.com/%s/%s"
	gitSuffix            = ".git"
)

// DistroRemoteURLs is the known set of possible git remote URLs of the distro
// repo.
func (ap AbsoluteProperties) DistroRemoteURLs() []string {
	return githubRemoteURLs(ap.DistroRepoOwner, ap.DistroPackagesRepo)
}

// AdvisoriesRemoteURLs is the known set of possible git remote URLs of the
// advisories repo.
func (ap AbsoluteProperties) AdvisoriesRemoteURLs() []string {
	return githubRemoteURLs(ap.DistroRepoOwner, ap.DistroAdvisoriesRepo)
}

func githubRemoteURLs(owner, repo string) []string {
	formats := []string{
		githubURLFormatGit,
		githubURLFormatHTTPS,
	}

	suffixes := []string{
		gitSuffix,
		"",
	}

	var urls []string
	for _, format := range formats {
		for _, suffix := range suffixes {
			urls = append(urls, fmt.Sprintf(format, owner, repo)+suffix)
		}
	}
	return urls
}

func (ap AbsoluteProperties) AdvisoriesHTTPSCloneURL() string {
	return fmt.Sprintf(githubURLFormatHTTPS, ap.DistroRepoOwner, ap.DistroAdvisoriesRepo) + gitSuffix
}

var (
	wolfiDistro = AbsoluteProperties{
		Name:                 "Wolfi",
		DistroRepoOwner:      "wolfi-dev",
		DistroPackagesRepo:   "os",
		DistroAdvisoriesRepo: "advisories",
		APKRepositoryURL:     "https://packages.wolfi.dev/os",
		SupportedArchitectures: []string{
			"x86_64",
			"aarch64",
		},
	}

	chainguardDistro = AbsoluteProperties{
		Name:                 "Enterprise Packages",
		DistroRepoOwner:      "chainguard-dev",
		DistroPackagesRepo:   "enterprise-packages",
		DistroAdvisoriesRepo: "enterprise-advisories",
		APKRepositoryURL:     "https://packages.cgr.dev/os",
		SupportedArchitectures: []string{
			"x86_64",
			"aarch64",
		},
	}

	extraPackagesDistro = AbsoluteProperties{
		Name:                 "Extra Packages",
		DistroRepoOwner:      "chainguard-dev",
		DistroPackagesRepo:   "extra-packages",
		DistroAdvisoriesRepo: "extra-advisories",
		APKRepositoryURL:     "https://packages.cgr.dev/extras",
		SupportedArchitectures: []string{
			"x86_64",
			"aarch64",
		},
	}
)
