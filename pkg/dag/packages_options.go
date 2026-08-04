package dag

type packagesOptions struct {
	// compileOnly limits melange compilation to these origin package names. A
	// nil map means every definition is compiled.
	compileOnly map[string]struct{}

	// dependenciesOnly compiles for build dependencies without producing
	// runnable pipelines.
	dependenciesOnly bool
}

type PackagesOption func(*packagesOptions) error

// WithCompileOnly limits melange pipeline compilation to the named origin
// packages.
//
// Compiling a definition resolves its `uses:` pipelines, which is what expands
// .environment.contents.packages and therefore supplies build-dependency edges.
// It is the dominant cost of NewPackages, and a caller that only needs those
// edges for a known subset - a presubmit that walks the graph for the packages
// a change touched, say - pays it for the whole repository.
//
// Definitions outside the set are still read, parsed, and registered along with
// their subpackages and provides, so the local index is the same either way and
// resolution is unaffected. What they lose is the packages a `uses:` pipeline
// would have added to their build environment, so their build-dependency edges
// are those written in the YAML and no others.
//
// Passing no names compiles everything, as if the option were not supplied.
func WithCompileOnly(names ...string) PackagesOption {
	return func(o *packagesOptions) error {
		if len(names) == 0 {
			return nil
		}
		if o.compileOnly == nil {
			o.compileOnly = make(map[string]struct{}, len(names))
		}
		for _, name := range names {
			o.compileOnly[name] = struct{}{}
		}
		return nil
	}
}

// WithDependenciesOnly compiles definitions for their build dependencies
// without producing runnable pipelines.
//
// Compiling resolves a definition's `uses:` pipelines, which is what expands
// .environment.contents.packages and supplies the build-dependency edges a
// graph is built from. Making the result runnable also normalizes each step's
// `runs:` body, which means shell-parsing and re-printing every script, and
// that is the larger half of what compiling costs.
//
// The Configurations left behind are not runnable: a step's `runs:` keeps the
// comments and formatting it was written with. Everything else - substitution,
// validation, conditionals, and the resolved dependency list - is unchanged, so
// a definition that fails to compile still fails the same way. Use this only to
// resolve dependencies, never to produce a configuration that will be built or
// recorded.
//
// It composes with WithCompileOnly: that one chooses which definitions are
// compiled, this one chooses how much of each compile is done.
func WithDependenciesOnly() PackagesOption {
	return func(o *packagesOptions) error {
		o.dependenciesOnly = true

		return nil
	}
}
