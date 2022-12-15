package lint

// Options represents the options to configure the linter.
type Options struct {
	// Path is the path to the file or directory to lint
	Path string

	// Verbose prints the details of the linting errors.
	Verbose bool

	// List prints the available linting rules.
	List bool
}

// Option represents a linter option.
type Option func(*Options)

// WithPath sets the path to the file or directory to lint.
func WithPath(path string) Option {
	return func(o *Options) {
		o.Path = path
	}
}

// WithVerbose sets the verbose option.
func WithVerbose(verbose bool) Option {
	return func(o *Options) {
		o.Verbose = verbose
	}
}

// WithList sets the list option.
func WithList(list bool) Option {
	return func(o *Options) {
		o.List = list
	}
}
