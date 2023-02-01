package configs

import (
	"fmt"
	"io/fs"
	"strings"

	"chainguard.dev/melange/pkg/build"
	"github.com/wolfi-dev/wolfictl/pkg/configs/rwfs"
	rwfsOS "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"gopkg.in/yaml.v3"
)

// An Index is a queryable store of Melange configurations, where each
// configuration has already been decoded both into the build.Configuration Go
// type and into a YAML AST.
type Index struct {
	fsys          rwfs.FS
	paths         []string
	yamlRoots     []*yaml.Node
	cfgs          []build.Configuration
	byID          map[string]int
	byPackageName map[string]int
	byPath        map[string]int
}

// NewIndex returns a new Index of all build configurations found within the
// given filesystem.
func NewIndex(fsys rwfs.FS) (*Index, error) {
	index := newIndex()
	index.fsys = fsys

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.Type().IsDir() && path != "." && strings.HasPrefix(d.Name(), ".") {
			return fs.SkipDir
		}

		if !d.Type().IsRegular() {
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

// NewIndexFromPaths returns a new Index of build configurations for each of the
// given paths.
func NewIndexFromPaths(baseDir string, paths ...string) (*Index, error) {
	index := newIndex()
	index.fsys = rwfsOS.DirFS(baseDir)

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

func newIndex() Index {
	index := Index{}
	index.byID = make(map[string]int)
	index.byPackageName = make(map[string]int)
	index.byPath = make(map[string]int)

	return index
}

// Select returns a Selection for the Index, which allows the caller to begin chaining selection clauses.
func (i *Index) Select() Selection {
	cfgs := i.Configurations()

	entries := make([]Entry, 0, len(cfgs))
	for idx := range cfgs {
		entries = append(entries, i.entry(idx))
	}

	return Selection{
		entries: entries,
		index:   i,
	}
}

// Configurations returns all parsed build configurations stored in the Index.
func (i *Index) Configurations() []build.Configuration {
	return i.cfgs
}

// Map applies the given predicate function to each entry in the given selection.
// It returns a slice of all predicate function outputs. If the predicate
// function returns an error, Map stops processing and returns that error to its
// caller.
func Map[T any](selection Selection, predicate func(Entry) (T, error)) ([]T, error) {
	result := make([]T, 0, len(selection.entries))

	for _, e := range selection.entries {
		t, err := predicate(e)
		if err != nil {
			return nil, err
		}

		result = append(result, t)
	}

	return result, nil
}

// FlatMap applies the given predicate function to each entry in the given
// selection. It returns all predicate function outputs, each of which is a
// slice, flattened into a single slice. If the predicate function returns an
// error, Map stops processing and returns that error to its caller.
func FlatMap[T any](selection Selection, predicate func(Entry) ([]T, error)) ([]T, error) {
	var result []T

	for _, e := range selection.entries {
		ts, err := predicate(e)
		if err != nil {
			return nil, err
		}

		result = append(result, ts...)
	}

	return result, nil
}

// update updates the given entry in the index using the provided updateFunc.
func (i *Index) update(entry Entry, updateFunc updateFunc) error {
	err := updateFunc(entry)
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

// processAndAdd parses the configuration file at the given path into both a YAML
// AST and a build.Configuration, and it then adds a new entry to the Index.
func (i *Index) processAndAdd(path string) error {
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

func (i *Index) processAndUpdate(path string, entryIndex int) error {
	entry, err := i.process(path)
	if err != nil {
		return err
	}
	i.updateAtIndex(entry, entryIndex)

	return nil
}

func (i *Index) process(path string) (*entry, error) {
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

	cfg, err := build.ParseConfiguration(path)
	if err != nil {
		return nil, fmt.Errorf("unable to parse configuration at %q: %w", path, err)
	}

	return &entry{
		path:     path,
		yamlRoot: yamlRoot,
		cfg:      cfg,
	}, nil
}

func (i *Index) add(e *entry) error {
	packageName := e.cfg.Package.Name
	if _, existsAlready := i.byPackageName[packageName]; existsAlready {
		return fmt.Errorf("unable to add configuration for package %q to index: package already added", packageName)
	}

	nextIndex := len(i.cfgs)
	i.paths = append(i.paths, e.path)
	i.yamlRoots = append(i.yamlRoots, e.yamlRoot)
	i.cfgs = append(i.cfgs, *e.cfg)

	i.byID[e.id()] = nextIndex
	i.byPath[e.path] = nextIndex
	i.byPackageName[packageName] = nextIndex

	return nil
}

func (i *Index) updateAtIndex(e *entry, entryIndex int) {
	i.paths[entryIndex] = e.path
	i.yamlRoots[entryIndex] = e.yamlRoot
	i.cfgs[entryIndex] = *e.cfg
	i.byID[e.id()] = entryIndex
	i.byPackageName[e.Configuration().Package.Name] = entryIndex
	i.byPath[e.Path()] = entryIndex
}

func (i *Index) entry(idx int) Entry {
	return entry{
		path:     i.paths[idx],
		yamlRoot: i.yamlRoots[idx],
		cfg:      &i.cfgs[idx],
	}
}
