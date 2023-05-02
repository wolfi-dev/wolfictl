package configs

import (
	"errors"
	"fmt"
)

// A Selection is a view into an Index's configuration (type T) entries. The
// selection can expose anywhere from zero entries up to all the index's
// entries. A selection allows the caller to chain methods to further constrain
// the selection and to perform operations on each item in the selection.
type Selection[T Configuration] struct {
	entries []Entry[T]
	index   *Index[T]
}

// WhereName filters the selection down to entries whose name match the given
// parameter.
func (s Selection[T]) WhereName(name string) Selection[T] {
	var entries []Entry[T]
	for _, e := range s.entries {
		cfg := e.Configuration()
		if cfg == nil {
			continue
		}
		if name == (*cfg).Name() {
			entries = append(entries, e)
		}
	}

	return Selection[T]{
		entries: entries,
		index:   s.index,
	}
}

// WhereFilePath filters the selection down to entries whose configuration file
// path match the given parameter.
func (s Selection[T]) WhereFilePath(p string) Selection[T] {
	var entries []Entry[T]
	for _, e := range s.entries {
		if p == e.Path() {
			entries = append(entries, e)
		}
	}

	return Selection[T]{
		entries: entries,
		index:   s.index,
	}
}

// Len returns the count of configurations in the Selection.
func (s Selection[T]) Len() int {
	return len(s.entries)
}

// UpdateEntries applies the given entryUpdater to all entries currently in the
// Selection.
func (s Selection[T]) UpdateEntries(entryUpdater EntryUpdater[T]) error {
	for _, e := range s.entries {
		err := s.index.update(e, entryUpdater)
		if err != nil {
			if errors.Is(err, ErrSkip) {
				continue
			}

			return fmt.Errorf("unable to update %q: %w", e.Path(), err)
		}
	}

	return nil
}

// Entries returns the Entry items included in the current Selection.
func (s Selection[T]) Entries() []Entry[T] {
	return s.entries
}
