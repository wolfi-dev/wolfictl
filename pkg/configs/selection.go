package configs

import (
	"context"
	"errors"

	"github.com/samber/lo"
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
	return s.Where(func(e Entry[T]) bool {
		cfg := e.Configuration()
		if cfg == nil {
			return false
		}

		return name == (*cfg).Name()
	})
}

// WhereFilePath filters the selection down to entries whose configuration file
// path match the given parameter.
func (s Selection[T]) WhereFilePath(p string) Selection[T] {
	return s.Where(func(e Entry[T]) bool {
		return p == e.getPath()
	})
}

// Where filters the selection down to entries for which the given condition is
// true.
func (s Selection[T]) Where(condition func(Entry[T]) bool) Selection[T] {
	var entries []Entry[T]
	for _, e := range s.entries {
		if condition(e) {
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

// Update applies the given entryUpdater to all entries currently in the
// Selection.
func (s Selection[T]) Update(ctx context.Context, entryUpdater EntryUpdater[T]) error {
	for _, e := range s.entries {
		err := e.Update(ctx, entryUpdater)
		if err != nil {
			if errors.Is(err, ErrSkip) {
				continue
			}

			return err
		}
	}

	return nil
}

// Each calls the given iterator function for each Entry in the Selection.
func (s Selection[T]) Each(iterator func(Entry[T])) {
	for _, e := range s.entries {
		iterator(e)
	}
}

// Entries returns the Entry items included in the current Selection.
func (s Selection[T]) Entries() []Entry[T] {
	return s.entries
}

// ErrNoEntries is returned when a Selection has no entries.
var ErrNoEntries = errors.New("no entries in selection")

// First returns the first Entry in the Selection.
func (s Selection[T]) First() (Entry[T], error) {
	if len(s.entries) == 0 {
		return nil, ErrNoEntries
	}

	return s.entries[0], nil
}

// Configurations returns the Configuration items included in the current Selection.
func (s Selection[T]) Configurations() []T {
	return lo.Map(s.entries, func(e Entry[T], _ int) T {
		cfg := e.Configuration()
		return *cfg
	})
}
