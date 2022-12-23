package configs

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"chainguard.dev/melange/pkg/build"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

// TODO: there are leaks in the entry abstraction for fs.FS. It'd be great to
// break out this FS abstraction and have this package be able to depend on that.

const yamlIndent = 2

// An Index is a queryable store of Melange configurations, where each
// configuration has already been decoded both into the build.Configuration Go
// type and into a YAML AST.
type Index struct {
	fsys          fs.FS
	paths         []string
	yamlRoots     []*yaml.Node
	cfgs          []build.Configuration
	byID          map[string]int
	byPackageName map[string]int
	byPath        map[string]int
}

// NewIndex returns a new Index of all build configurations found within the
// given filesystem.
func NewIndex(fsys fs.FS) (*Index, error) {
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
func NewIndexFromPaths(paths ...string) (*Index, error) {
	index := newIndex()

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

var EntryNotFound = errors.New("index entry not found")

type GetByFunc func(i *Index) (Entry, error)

func ByID(id string) GetByFunc {
	return func(i *Index) (Entry, error) {
		entryIdx, ok := i.byID[id]
		if !ok {
			return nil, EntryNotFound
		}
		return i.entry(entryIdx), nil
	}
}

func ByPackageName(name string) GetByFunc {
	return func(i *Index) (Entry, error) {
		entryIdx, ok := i.byPackageName[name]
		if !ok {
			return nil, EntryNotFound
		}
		return i.entry(entryIdx), nil
	}
}

func ByPath(path string) GetByFunc {
	return func(i *Index) (Entry, error) {
		entryIdx, ok := i.byPath[path]
		if !ok {
			return nil, EntryNotFound
		}
		return i.entry(entryIdx), nil
	}
}

// Get finds an Entry in the index using the provided GetByFunc, such as ByID,
// ByPackageName, or ByPath.
func (i *Index) Get(by GetByFunc) (Entry, error) {
	return by(i)
}

// Configurations returns all parsed build configurations stored in the Index.
func (i *Index) Configurations() []build.Configuration {
	return i.cfgs
}

type IndexEntryFunc func(entry Entry) error

// ForEach applies the given IndexEntryFunc to every item in the Index. If the
// given func returns an error, ForEach stops iterating and returns that error to
// the caller.
func (i *Index) ForEach(f IndexEntryFunc) error {
	for entryIdx := range i.cfgs {
		e := entry{
			path:     i.paths[entryIdx],
			yamlRoot: i.yamlRoots[entryIdx],
			cfg:      &i.cfgs[entryIdx],
		}

		err := f(e)
		if err != nil {
			return err
		}
	}

	return nil
}

// Update updates the given entry in the index using the provided UpdateFunc.
func (i *Index) Update(entry Entry, updateFunc UpdateFunc) error {
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

func (i *Index) openFile(entryID string) (fs.File, error) {
	path := i.getEntry(entryID).Path()

	if i.fsys != nil {
		return i.fsys.Open(path)
	}

	return os.Open(path)
}

func (i *Index) openWriteableFile(entryID string) (io.ReadWriteCloser, error) {
	// TODO: fix leaky abstraction!

	path := i.getEntry(entryID).Path()
	return os.OpenFile(path, os.O_RDWR, 06755)
}

type UpdateFunc func(Entry) error

type YAMLUpdater func(node *yaml.Node) error

func (i *Index) NewUpdater(updateYAML YAMLUpdater) UpdateFunc {
	return func(e Entry) error {
		cfgFile, err := i.openFile(e.id())
		if err != nil {
			return err
		}
		defer cfgFile.Close()

		root := e.YAMLRoot()

		err = updateYAML(root)
		if err != nil {
			return err
		}

		writableCfgFile, err := i.openWriteableFile(e.id())
		if err != nil {
			return err
		}
		defer writableCfgFile.Close()

		encoder := yaml.NewEncoder(writableCfgFile)
		encoder.SetIndent(yamlIndent)
		err = encoder.Encode(root)
		if err != nil {
			return err
		}

		return nil
	}
}

// processAndAdd parses the configuration file at the given path into both a YAML
// AST and a build.Configuration, and it then adds a new entry to the Index.
//
// processAndAdd uses the fsys parameter to open the given path, if fsys is not
// nil; otherwise, it uses os.Open.
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
	i.update(entry, entryIndex)

	return nil
}

func (i *Index) process(path string) (*entry, error) {
	// TODO: for the follow operations, consider noting the error and moving on, rather than stopping the indexing.

	var f fs.File
	var err error
	if i.fsys != nil {
		f, err = i.fsys.Open(path)
		if err != nil {
			return nil, fmt.Errorf("unable to open configuration at %q: %w", path, err)
		}
	} else {
		f, err = os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("unable to open configuration at %q: %w", path, err)
		}
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

func (i *Index) update(e *entry, entryIndex int) {
	i.paths[entryIndex] = e.path
	i.yamlRoots[entryIndex] = e.yamlRoot
	i.cfgs[entryIndex] = *e.cfg
	i.byID[e.id()] = entryIndex
	i.byPackageName[e.Configuration().Package.Name] = entryIndex
	i.byPath[e.Path()] = entryIndex
}

func (i *Index) getEntry(id string) Entry {
	entryIndex := i.byID[id]
	return i.entry(entryIndex)
}

func (i *Index) entry(idx int) Entry {
	return entry{
		path:     i.paths[idx],
		yamlRoot: i.yamlRoots[idx],
		cfg:      &i.cfgs[idx],
	}
}
