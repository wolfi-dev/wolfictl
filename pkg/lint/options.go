package lint

// Options represents the options to configure the linter.
type Options struct {
	// Path is the path to the file or directory to lint
	Path string

	// Skip rules removes the given slice of rules to be checked
	SkipRules []string
}

// Option represents a linter option.
type Option func(*Options)

// WithPath sets the path to the file or directory to lint.
func WithPath(path string) Option {
	return func(o *Options) {
		o.Path = path
	}
}

// WithSkipRules sets the skip rules option.
func WithSkipRules(skipRules []string) Option {
	return func(o *Options) {
		o.SkipRules = skipRules
	}
}
