package dag

type graphOptions struct {
	allowUnresolved bool
	repos           []string
	keys            []string
}

type GraphOptions func(*graphOptions) error

func WithAllowUnresolved() GraphOptions {
	return func(o *graphOptions) error {
		o.allowUnresolved = true
		return nil
	}
}

func WithRepos(repos ...string) GraphOptions {
	return func(o *graphOptions) error {
		o.repos = repos
		return nil
	}
}

func WithKeys(keys ...string) GraphOptions {
	return func(o *graphOptions) error {
		o.keys = keys
		return nil
	}
}
