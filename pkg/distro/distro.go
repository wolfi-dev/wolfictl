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

	extraPackagesDistro = AbsoluteProperties{
		Name: "Extra Packages",
		DistroRemoteURLs: []string{
			"git@github.com:chainguard-dev/extra-packages.git",
			"git@github.com:chainguard-dev/extra-packages",
			"https://github.com/chainguard-dev/extra-packages.git",
			"https://github.com/chainguard-dev/extra-packages",
		},
		AdvisoriesRemoteURLs: []string{
			"git@github.com:chainguard-dev/extra-advisories.git",
			"git@github.com:chainguard-dev/extra-advisories",
			"https://github.com/chainguard-dev/extra-advisories.git",
			"https://github.com/chainguard-dev/extra-advisories",
		},
		APKRepositoryURL: "https://packages.cgr.dev/extras",
		SupportedArchitectures: []string{
			"x86_64",
			"aarch64",
		},
	}
)
