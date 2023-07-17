package dag

type graphOptions struct {
	allowUnresolved          bool
	repos                    []string
	keys                     []string
	runtimeRepos             []string
	runtimeKeys              []string
	buildtimeReposForRuntime bool
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

// WithRuntimeRepos add repos for resolution of the
// runtime graph, i.e. package.dependencies.runtime.
// Always includes packages in the local repository in which
// this package is defined. Optionally, you can add
// other repositories.
func WithRuntimeRepos(repos ...string) GraphOptions {
	return func(o *graphOptions) error {
		o.runtimeRepos = repos
		return nil
	}
}

// WithRuntimeKeys add keys for validating
// repositories referenced in the
// runtime graph, i.e. package.dependencies.runtime.
// The local repository in which this package is defined does not
// need additional keys. Normally used in concert with WithRuntimeRepos.
func WithRuntimeKeys(keys ...string) GraphOptions {
	return func(o *graphOptions) error {
		o.runtimeKeys = keys
		return nil
	}
}

// WithBuildtimeReposRuntime add any repos and keys used for
// buildtime resolution at runtime. If this is set to true,
// all buildtime repositories and keys, i.e. those defined in
// environments.contents.repositories and environments.contents.keys,
// will be used for runtime resolution as well, i.e. package.dependencies.runtime.
func WithBuildtimeReposRuntime(use bool) GraphOptions {
	return func(o *graphOptions) error {
		o.buildtimeReposForRuntime = use
		return nil
	}
}
