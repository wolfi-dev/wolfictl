package distro

// Distro represents a wolfictl-compatible distro, along with important
// properties discovered about how the user interacts with the distro.
type Distro struct {
	Local    LocalProperties
	Absolute AbsoluteProperties
}

// LocalProperties describe the aspects of the distro that are specific to the
// context of the user's local environment.
type LocalProperties struct {
	// DistroRepoDir is the path to the directory containing the user's clone of the
	// distro repo, i.e. the repo containing the distro's build configurations.
	DistroRepoDir string

	// AdvisoriesRepoDir is the path to the directory containing the user's clone of
	// the advisories repo, i.e. the repo containing the distro's advisory data.
	AdvisoriesRepoDir string
}

// AbsoluteProperties describe the aspects of the distro that are constant and
// not a function of any user's local environment.
type AbsoluteProperties struct {
	// The Name of the distro, e.g. "Wolfi".
	Name string

	// The known possible git remote URLs of the distro repo.
	DistroRemoteURLs []string

	// The known possible git remote URLs of the distro's advisories repo.
	AdvisoriesRemoteURLs []string

	// APKRepositoryURL is the URL to the distro's package repository (e.g.
	// "https://packages.wolfi.dev/os").
	APKRepositoryURL string

	// SupportedArchitectures is a list of architectures supported by the distro.
	SupportedArchitectures []string
}

var (
	wolfiDistro = AbsoluteProperties{
		Name: "Wolfi",
		DistroRemoteURLs: []string{
			"git@github.com:wolfi-dev/os.git",
			"git@github.com:wolfi-dev/os",
			"https://github.com/wolfi-dev/os.git",
			"https://github.com/wolfi-dev/os",
		},
		AdvisoriesRemoteURLs: []string{
			"git@github.com:wolfi-dev/advisories.git",
			"git@github.com:wolfi-dev/advisories",
			"https://github.com/wolfi-dev/advisories.git",
			"https://github.com/wolfi-dev/advisories",
		},
		APKRepositoryURL: "https://packages.wolfi.dev/os",
		SupportedArchitectures: []string{
			"x86_64",
			"aarch64",
		},
	}

	chainguardDistro = AbsoluteProperties{
		Name: "Chainguard",
		DistroRemoteURLs: []string{
			"git@github.com:chainguard-dev/enterprise-packages.git",
			"git@github.com:chainguard-dev/enterprise-packages",
			"https://github.com/chainguard-dev/enterprise-packages.git",
			"https://github.com/chainguard-dev/enterprise-packages",
		},
		AdvisoriesRemoteURLs: []string{
			"git@github.com:chainguard-dev/enterprise-advisories.git",
			"git@github.com:chainguard-dev/enterprise-advisories",
			"https://github.com/chainguard-dev/enterprise-advisories.git",
			"https://github.com/chainguard-dev/enterprise-advisories",
		},
		APKRepositoryURL: "https://packages.cgr.dev/os",
		SupportedArchitectures: []string{
			"x86_64",
			"aarch64",
		},
	}
)
