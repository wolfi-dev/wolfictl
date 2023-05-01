package configs

import (
	"fmt"
	"io/fs"
	"strings"

	"github.com/pkg/errors"
	"github.com/wolfi-dev/wolfictl/pkg/configs/rwfs"
	"gopkg.in/yaml.v3"
)

// Configuration describes any type that can be named (such as a package
// configuration struct, where the package has name (e.g. "busybox") that's a
// meaningful key for indexing the configuration itself.)
type Configuration interface {
	Name() string
}

// An Index is a queryable store of configurations, where each configuration has
// already been decoded both into the configuration Go type (T) and into a YAML
// AST.
type Index[T Configuration] struct {
	fsys          rwfs.FS
	paths         []string
	yamlRoots     []*yaml.Node
	cfgs          []T
	cfgDecodeFunc func(string) (*T, error)
	byID          map[string]int
	byName        map[string]int
	byPath        map[string]int
}

// NewIndex returns a new Index of all configurations found within the given
// filesystem. The provided cfgDecodeFunc should take a path to a YAML file in a
// fs.FS, decode the file to type T, and return a reference the "type T" data,
// or an error if there was a problem.
func NewIndex[T Configuration](fsys rwfs.FS, cfgDecodeFunc func(string) (*T, error)) (*Index[T], error) {
	if cfgDecodeFunc == nil {
		return nil, errors.New("must supply a cfgDecodeFunc")
	}

	index := newIndex(cfgDecodeFunc)
	index.fsys = fsys

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.Type().IsDir() && path != "." {
			return fs.SkipDir
		}

		if !d.Type().IsRegular() {
			return nil
		}

		if strings.HasPrefix(d.Name(), ".") {
			return nil
		}

		if !strings.HasSuffix(d.Name(), ".yaml") {
			return nil
		}

		err = index.processAndAdd(path)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &index, nil
}

// NewIndexFromPaths returns a new Index of configurations for each of the given
// paths. The provided cfgDecodeFunc should take a path to a YAML file in a
// fs.FS, decode the file to type T, and return a reference the "type T" data,
// or an error if there was a problem.
func NewIndexFromPaths[T Configuration](fsys rwfs.FS, cfgDecodeFunc func(string) (*T, error), paths ...string) (*Index[T], error) {
	index := newIndex(cfgDecodeFunc)
	index.fsys = fsys

	for _, path := range paths {
		err := index.processAndAdd(path)
		if err != nil {
			return nil, err
		}
		if err != nil {
			return nil, fmt.Errorf("unable to create configuration index: %w", err)
		}
	}

	return &index, nil
}

func newIndex[T Configuration](cfgDecodeFunc func(string) (*T, error)) Index[T] {
	index := Index[T]{}
	index.cfgDecodeFunc = cfgDecodeFunc
	index.byID = make(map[string]int)
	index.byName = make(map[string]int)
	index.byPath = make(map[string]int)

	return index
}

// Select returns a Selection for the Index, which allows the caller to begin chaining selection clauses.
func (i *Index[T]) Select() Selection[T] {
	cfgs := i.Configurations()

	entries := make([]Entry[T], 0, len(cfgs))
	for idx := range cfgs {
		entries = append(entries, i.entry(idx))
	}

	return Selection[T]{
		entries: entries,
		index:   i,
	}
}

// Configurations returns all decoded configurations stored in the Index.
func (i *Index[T]) Configurations() []T {
	return i.cfgs
}

// FlatMap applies the given predicate function to each entry in the given
// selection. It returns all predicate function outputs, each of which is a
// slice, flattened into a single slice. If the predicate function returns an
// error, Map stops processing and returns that error to its caller.
func FlatMap[K any, T Configuration](selection Selection[T], predicate func(Entry[T]) ([]K, error)) ([]K, error) {
	var result []K

	for _, e := range selection.entries {
		ts, err := predicate(e)
		if err != nil {
			return nil, err
		}

		result = append(result, ts...)
	}

	return result, nil
}

// update updates the given entry in the index using the provided EntryUpdater.
func (i *Index[T]) update(entry Entry[T], entryUpdater EntryUpdater[T]) error {
	err := entryUpdater(i, entry)
	if err != nil {
		return err
	}

	id := entry.id()
	err = i.processAndUpdate(entry.Path(), i.byID[id])
	if err != nil {
		return fmt.Errorf("unable to process and update index entry for %q: %w", id, err)
	}

	return nil
}

// processAndAdd decodes the configuration file at the given path into both a
// YAML AST and a configuration (type T), and it then adds a new entry to the
// Index.
func (i *Index[T]) processAndAdd(path string) error {
	entry, err := i.process(path)
	if err != nil {
		return err
	}
	err = i.add(entry)
	if err != nil {
		return fmt.Errorf("unable to add entry to index for %q: %w", path, err)
	}

	return nil
}

func (i *Index[T]) processAndUpdate(path string, entryIndex int) error {
	entry, err := i.process(path)
	if err != nil {
		return err
	}
	i.updateAtIndex(entry, entryIndex)

	return nil
}

func (i *Index[T]) process(path string) (*entry[T], error) {
	// TODO: for the follow operations, consider noting the error and moving on, rather than stopping the indexing.

	f, err := i.fsys.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open configuration at %q: %w", path, err)
	}

	yamlRoot := &yaml.Node{}
	err = yaml.NewDecoder(f).Decode(yamlRoot)
	if err != nil {
		return nil, fmt.Errorf("unable to decode YAML at %q: %w", path, err)
	}

	cfg, err := i.cfgDecodeFunc(path)
	if err != nil {
		return nil, fmt.Errorf("unable to parse configuration at %q: %w", path, err)
	}

	return &entry[T]{
		path:     path,
		yamlRoot: yamlRoot,
		cfg:      *cfg,
	}, nil
}

func (i *Index[T]) add(e *entry[T]) error {
	cfg := e.Configuration()
	if cfg == nil {
		return errors.New("entry's configuration was nil")
	}

	name := (*cfg).Name()
	if _, existsAlready := i.byName[name]; existsAlready {
		return fmt.Errorf("unable to add configuration (for item named %q) to index: name already used by existing item", name)
	}

	nextIndex := len(i.cfgs)
	i.paths = append(i.paths, e.path)
	i.yamlRoots = append(i.yamlRoots, e.yamlRoot)
	i.cfgs = append(i.cfgs, e.cfg)

	i.byID[e.id()] = nextIndex
	i.byPath[e.path] = nextIndex
	i.byName[name] = nextIndex

	return nil
}

func (i *Index[T]) updateAtIndex(e *entry[T], entryIndex int) {
	i.paths[entryIndex] = e.path
	i.yamlRoots[entryIndex] = e.yamlRoot
	i.cfgs[entryIndex] = e.cfg
	i.byID[e.id()] = entryIndex
	i.byName[(*e.Configuration()).Name()] = entryIndex
	i.byPath[e.Path()] = entryIndex
}

func (i *Index[T]) entry(idx int) Entry[T] {
	return entry[T]{
		path:     i.paths[idx],
		yamlRoot: i.yamlRoots[idx],
		cfg:      i.cfgs[idx],
	}
}
