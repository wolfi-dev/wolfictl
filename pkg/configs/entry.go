package configs

import (
	"gopkg.in/yaml.v3"
)

// Entry represents an individual item in the Index.
type Entry[T Configuration] interface {
	id() string

	// yamlASTRoot returns the entry as a decoded YAML AST (via its root node).
	yamlASTRoot() *yaml.Node

	// Path returns the path of the configuration file that underlies this index entry.
	Path() string

	// Configuration returns the entry as a decoded configuration.
	Configuration() *T
}

type entry[T Configuration] struct {
	path     string
	yamlRoot *yaml.Node
	cfg      T
}

func (e entry[T]) id() string {
	return e.path
}

//nolint:unused // linter is just wrong? This is used in yaml.go.
func (e entry[T]) yamlASTRoot() *yaml.Node {
	return e.yamlRoot
}

func (e entry[T]) Path() string {
	return e.path
}

func (e entry[T]) Configuration() *T {
	return &e.cfg
}
