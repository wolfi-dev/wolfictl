package distro

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

	// SupportedArchitectures is a list of architectures supported by the distro.
	SupportedArchitectures []string
}

type knownDistro struct {
	name                                   string
	distroRemoteURLs, advisoriesRemoteURLs []string
	apkRepositoryURL                       string
	supportedArchitectures                 []string
}

var (
	wolfiDistro = knownDistro{
		name: "Wolfi",
		distroRemoteURLs: []string{
			"git@github.com:wolfi-dev/os.git",
			"git@github.com:wolfi-dev/os",
			"https://github.com/wolfi-dev/os.git",
			"https://github.com/wolfi-dev/os",
		},
		advisoriesRemoteURLs: []string{
			"git@github.com:wolfi-dev/advisories.git",
			"git@github.com:wolfi-dev/advisories",
			"https://github.com/wolfi-dev/advisories.git",
			"https://github.com/wolfi-dev/advisories",
		},
		apkRepositoryURL: "https://packages.wolfi.dev/os",
		supportedArchitectures: []string{
			"x86_64",
			"aarch64",
		},
	}

	chainguardDistro = knownDistro{
		name: "Chainguard",
		distroRemoteURLs: []string{
			"git@github.com:chainguard-dev/enterprise-packages.git",
			"git@github.com:chainguard-dev/enterprise-packages",
			"https://github.com/chainguard-dev/enterprise-packages.git",
			"https://github.com/chainguard-dev/enterprise-packages",
		},
		advisoriesRemoteURLs: []string{
			"git@github.com:chainguard-dev/enterprise-advisories.git",
			"git@github.com:chainguard-dev/enterprise-advisories",
			"https://github.com/chainguard-dev/enterprise-advisories.git",
			"https://github.com/chainguard-dev/enterprise-advisories",
		},
		apkRepositoryURL: "https://packages.cgr.dev/os",
		supportedArchitectures: []string{
			"x86_64",
			"aarch64",
		},
	}
)
