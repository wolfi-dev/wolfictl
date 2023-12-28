package dag

type graphOptions struct {
	allowUnresolved bool
	repos           []string
	keys            []string
	arch            string
}

type GraphOptions func(*graphOptions) error

func WithAllowUnresolved() GraphOptions {
	return func(o *graphOptions) error {
		o.allowUnresolved = true
		return nil
	}
}

// WithRepos add repos for resolution of the
// buildtime graph, i.e. environments.contents.packages.
// Always includes packages in the local repository in which
// this package is defined. Optionally, you can add
// other repositories.
func WithRepos(repos ...string) GraphOptions {
	return func(o *graphOptions) error {
		o.repos = repos
		return nil
	}
}

// WithKeys add keys for validating
// repositories referenced in the
// buildtime graph, i.e. environments.contents.packages.
// The local repository in which this package is defined does not
// need additional keys. Normally used in concert with WithRepos.
func WithKeys(keys ...string) GraphOptions {
	return func(o *graphOptions) error {
		o.keys = keys
		return nil
	}
}

// WithArch sets the architecture for which the graph is built.
func WithArch(arch string) GraphOptions {
	return func(o *graphOptions) error {
		o.arch = arch
		return nil
	}
}
