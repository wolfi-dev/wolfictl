package configs

import (
	"context"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Entry represents an individual item in the Index.
type Entry[T Configuration] interface {
	// getIndex returns the Index that this entry belongs to.
	getIndex() *Index[T]

	// id returns a unique identifier for the entry.
	id() string

	// yamlASTRoot returns the entry as a decoded YAML AST (via its root node).
	yamlASTRoot() *yaml.Node

	// Path returns the path of the configuration file that underlies this index entry.
	getPath() string

	// Update applies the given entryUpdater to the entry.
	Update(ctx context.Context, updater EntryUpdater[T]) error

	// Configuration returns the entry as a decoded configuration.
	Configuration() *T
}

type entry[T Configuration] struct {
	index    *Index[T]
	path     string
	yamlRoot *yaml.Node
	cfg      T
}

func (e entry[T]) getIndex() *Index[T] {
	return e.index
}

func (e entry[T]) id() string {
	return e.path
}

//nolint:unused // linter is just wrong? This is used in yaml.go.
func (e entry[T]) yamlASTRoot() *yaml.Node {
	return e.yamlRoot
}

func (e entry[T]) getPath() string {
	return e.path
}

func (e entry[T]) Update(ctx context.Context, updater EntryUpdater[T]) error {
	err := e.getIndex().update(ctx, e, updater)
	if err != nil {
		return fmt.Errorf("unable to update %q: %w", e.id(), err)
	}

	return nil
}

func (e entry[T]) Configuration() *T {
	return &e.cfg
}
