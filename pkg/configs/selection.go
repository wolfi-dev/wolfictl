package configs

// A Selection is a view into an Index's configuration entries. The selection can
// expose anywhere from zero entries up to all the index's entries. A selection
// allows the caller to chain methods to further constrain the selection and to
// perform operations on each item in the selection.
type Selection struct {
	entries []Entry
	index   *Index
}

// WherePackageName filters the selection down to entries whose package name
// match the given parameter.
func (s Selection) WherePackageName(name string) Selection {
	var entries []Entry
	for _, e := range s.entries {
		cfg := e.Configuration()
		if cfg == nil {
			continue
		}
		if name == cfg.Package.Name {
			entries = append(entries, e)
		}
	}

	return Selection{
		entries: entries,
		index:   s.index,
	}
}

// WhereFilePath filters the selection down to entries whose configuration file
// path match the given parameter.
func (s Selection) WhereFilePath(p string) Selection {
	var entries []Entry
	for _, e := range s.entries {
		if p == e.Path() {
			entries = append(entries, e)
		}
	}

	return Selection{
		entries: entries,
		index:   s.index,
	}
}

// Len returns the count of configurations in the Selection.
func (s Selection) Len() int {
	return len(s.entries)
}
