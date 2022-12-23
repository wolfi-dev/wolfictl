package configs

import (
	"chainguard.dev/melange/pkg/build"
	"gopkg.in/yaml.v3"
)

// Entry represents an individual item in the Index.
type Entry interface {
	id() string

	// Path returns the path of the configuration file that underlies this index entry.
	Path() string

	// YAMLRoot returns the entry as a decoded YAML AST (via its root node).
	YAMLRoot() *yaml.Node

	// Configuration returns the entry as a decoded build.Configuration.
	Configuration() *build.Configuration
}

type entry struct {
	path     string
	yamlRoot *yaml.Node
	cfg      *build.Configuration
}

func (e entry) id() string {
	return e.path
}

func (e entry) Path() string {
	return e.path
}

func (e entry) YAMLRoot() *yaml.Node {
	return e.yamlRoot
}

func (e entry) Configuration() *build.Configuration {
	return e.cfg
}
