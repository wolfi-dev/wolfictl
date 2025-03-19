package testerfs

import (
	"bytes"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/samber/lo"
	"github.com/wolfi-dev/wolfictl/pkg/configs/rwfs"
)

const expectedSuffix = "_expected"
const specialFileContentForSkippingDiff = "# skip"

var _ rwfs.FS = (*FS)(nil)

type FS struct {
	underlying             fs.FS
	rootDir                string
	fixtures               map[string]*testFile
	dirPathToChildrenPaths map[string][]string
	logger                 *slog.Logger
}

// New returns a new testerfs.FS that wraps the given fs.FS. The returned
// testerfs.FS will only persist changes in-memory, and it will be possible to
// diff the changes made to the testerfs.FS against the "expected" file contents
// for each corresponding file in the test fixture.
func New(underlying fs.FS) (*FS, error) {
	return newFromOpts(opts{
		underlying: underlying,
	})
}

// NewWithLogger does the same thing as calling New, but injects a logger for
// observing noteworthy filesystem activity.
func NewWithLogger(underlying fs.FS, logger *slog.Logger) (*FS, error) {
	return newFromOpts(opts{
		underlying: underlying,
		logger:     logger,
	})
}

func NewWithRoot(root string) (*FS, error) {
	underlying := os.DirFS(root)
	return newFromOpts(opts{
		underlying: underlying,
	})
}

// NewWithFileMask returns a new testerfs.FS that wraps the given fs.FS. The
// returned testerfs.FS will only cover files from the underlying FS that are
// present in the given paths. This is useful for testing a specific subset of a
// larger test fixture.
func NewWithFileMask(underlying fs.FS, paths ...string) (*FS, error) {
	return newFromOpts(opts{
		underlying: underlying,
		mask:       paths,
	})
}

func newFromOpts(opts opts) (*FS, error) {
	const rootDirPath = "."

	testerFS := &FS{
		underlying:             opts.underlying,
		rootDir:                rootDirPath,
		fixtures:               make(map[string]*testFile),
		dirPathToChildrenPaths: make(map[string][]string),
		logger:                 opts.logger,
	}

	testerFS.registerDir(rootDirPath)

	// Keep track of expected files that don't have a corresponding original file.
	// We'll explicitly add these to the system at the end. This is useful for tests
	// where the code under test is expected to create a new file with the expected
	// contents.
	seenOriginalPaths := make(map[string]struct{})
	seenExpectedPaths := make(map[string]struct{})

	if err := fs.WalkDir(testerFS.underlying, rootDirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if filepath.Base(path) == ".gitkeep" {
			// ignore
			return nil
		}

		if path != "." && len(opts.mask) > 0 {
			// If a mask is provided, skip any paths that don't match the mask. Also infer
			// expected files that should be included implicitly by the mask elements.

			allowed := false
			for _, m := range opts.mask {
				if path == m || path == expectedName(m) {
					// This is a match.
					allowed = true
					break
				}
			}

			if !allowed {
				// This is not a match.
				if log := testerFS.logger; log != nil {
					log.Info("skipping path not in mask", "path", path)
				}
				return nil
			}
		}

		// Ensure all parent directories are registered.
		dir, file := filepath.Split(path)
		if dir != "" {
			testerFS.registerDir(dir)

			if file != "" {
				testerFS.dirPathToChildrenPaths[dir] = append(testerFS.dirPathToChildrenPaths[dir], path)
			}
		} else if file != "" && file != rootDirPath && !isExpectedFile(path) {
			// The parent is the root directory, and the current path is the root directory,
			// nor is the current path an "expected" file. We already registered the root
			// directory, but let's capture the parent-child relationship.
			testerFS.dirPathToChildrenPaths[rootDirPath] = append(testerFS.dirPathToChildrenPaths[rootDirPath], path)
		}

		if d.Type().IsDir() {
			testerFS.registerDir(path)
			return nil
		}

		if d.Type().IsRegular() {
			if isExpectedFile(path) {
				seenExpectedPaths[path] = struct{}{}

				// This is a special file for this tester.FS! Skip. We'll load it at the same
				// time as loading the original file.
				return nil
			}

			seenOriginalPaths[path] = struct{}{}

			if err := testerFS.addOriginalAndExpectedFilesAtPath(path); err != nil {
				return fmt.Errorf("adding fixture file: %w", err)
			}
		}

		return nil
	}); err != nil {
		return nil, fmt.Errorf("walking fixture directory: %w", err)
	}

	// Add any expected files that don't have a corresponding original file.
	for expectedPath := range seenExpectedPaths {
		if _, ok := seenOriginalPaths[originalName(expectedPath)]; !ok {
			if err := testerFS.addOnlyExpectedFileAtPath(expectedPath); err != nil {
				return nil, fmt.Errorf("adding fixture file: %w", err)
			}
		}
	}

	return testerFS, nil
}

type opts struct {
	underlying fs.FS
	logger     *slog.Logger
	mask       []string
}

// ReadDir implements fs.ReadDirFS.
func (fsys FS) ReadDir(name string) ([]fs.DirEntry, error) {
	if log := fsys.logger; log != nil {
		log.Debug("tester.FS: ReadDir", "name", name)
	}

	if _, ok := fsys.fixtures[name]; !ok {
		return nil, fs.ErrNotExist
	}

	if childrenPaths, ok := fsys.dirPathToChildrenPaths[name]; ok {
		var dirEntries []fs.DirEntry
		for _, p := range childrenPaths {
			tf, ok := fsys.fixtures[p]
			if !ok {
				return nil, fmt.Errorf("expected to be able to return a testFile for %q", p)
			}
			if tf.missingOriginal {
				continue
			}
			dirEntries = append(dirEntries, tf)
		}
		return dirEntries, nil
	}

	// No children for this directory.
	return nil, nil
}

// isExpectedFile returns true if the given path is an "expected" file.
//
// For example, this would return true for the following inputs:
// - "foo/bar/baz_expected.yaml"
// - "foo/bar/baz_expected.special.yaml"
// - "baz_expected"
//
// ...but not for these inputs:
// - "foo/bar/baz.yaml"
// - "foo/bar/foo.yaml_expected"
func isExpectedFile(path string) bool {
	file := filepath.Base(path)
	parts := strings.Split(file, ".")

	return strings.HasSuffix(parts[0], expectedSuffix)
}

// expectedName returns the expected name for a given original file. "expected
// files" are designated by having "_expected" to the filename before any
// extension. For example, "foo/bar/baz.special.yaml" would have an expected
// file of "foo/bar/baz_expected.special.yaml".
func expectedName(original string) string {
	dir, file := filepath.Split(original)
	parts := strings.Split(file, ".")

	if len(parts) == 1 {
		return filepath.Join(dir, parts[0]+expectedSuffix)
	}

	parts[0] += expectedSuffix
	expectedFile := strings.Join(parts, ".")

	return filepath.Join(dir, expectedFile)
}

// originalName returns the original name for a given expected file. "expected
// files" are designated by having "_expected" to the filename before any
// extension. For example, "foo/bar/baz_expected.special.yaml" would have an
// original file of "foo/bar/baz.special.yaml".
func originalName(expected string) string {
	dir, file := filepath.Split(expected)
	parts := strings.Split(file, ".")

	if len(parts) == 1 {
		return filepath.Join(dir, strings.TrimSuffix(parts[0], expectedSuffix))
	}

	parts[0] = strings.TrimSuffix(parts[0], expectedSuffix)
	originalFile := strings.Join(parts, ".")

	return filepath.Join(dir, originalFile)
}

// Create helps implement the rwfs.FS interface. The new file is persisted only
// in-memory, and will serve as the "actual" contents for the given path.
func (fsys *FS) Create(name string) (rwfs.File, error) {
	if log := fsys.logger; log != nil {
		log.Debug("tester.FS: Create", "name", name)
	}

	var tf *testFile
	if f, ok := fsys.fixtures[name]; ok {
		// The file already exists in the tester.FS, presumably because it was
		// already registered via its expected file.
		tf = f
		tf.missingOriginal = false
	} else {
		tf := new(testFile)
		tf.path = name

		tf.originalReader = bytes.NewReader(nil)
	}

	tf.writtenBack = new(bytes.Buffer)
	fsys.registerTestFile(name, tf)
	return tf, nil
}

// Open implements fs.FS.
func (fsys *FS) Open(name string) (fs.File, error) {
	if log := fsys.logger; log != nil {
		log.Debug("tester.FS: Open", "name", name)
	}

	if f, ok := fsys.fixtures[name]; ok {
		if f.isDir {
			// The file is a directory, no need to worry about byte reading.
			return f, nil
		}

		if f.writtenTo {
			// Reinitialize the reader over the written back buffer. If the file was
			// fully-read last time it was opened, calls to the file's Read method shouldn't
			// be allowed to return EOF again.
			f.writtenBackReader = bytes.NewReader(f.writtenBack.Bytes())
		} else {
			f.originalReader = bytes.NewReader(f.originalBytes)
		}
		return f, nil
	}

	return nil, fs.ErrNotExist
}

// OpenAsWritable implements rwfs.FS.
func (fsys *FS) OpenAsWritable(name string) (rwfs.File, error) {
	if log := fsys.logger; log != nil {
		log.Debug("tester.FS: OpenAsWritable", "name", name)
	}

	if f, ok := fsys.fixtures[name]; ok {
		return f, nil
	}

	return nil, fs.ErrNotExist
}

// Truncate implements rwfs.FS.
func (fsys *FS) Truncate(name string, n int64) error {
	if log := fsys.logger; log != nil {
		log.Debug("tester.FS: Truncate", "name", name)
	}

	// NOTE: For now, only truncated to 0 is supported!
	if n != 0 {
		return fmt.Errorf("only truncating to 0 is supported")
	}

	f, ok := fsys.fixtures[name]
	if !ok {
		return fmt.Errorf("file not found: %s", name)
	}

	// Clear the file contents by resetting the buffer.
	f.writtenBack.Reset()

	// Also reset the reader so future reads don’t return old data.
	f.writtenBackReader = bytes.NewReader(nil)

	return nil
}

// Diff returns a human-readable diff between the expected and actual contents
// for the given file path. If there is no diff, an empty string is returned.
func (fsys *FS) Diff(name string) string {
	if tf, ok := fsys.fixtures[name]; ok {
		want := tf.expectedRead.Bytes()
		var got []byte

		if !tf.writtenTo {
			// The file was never written to, so from a filesystem perspective, it still has
			// the original bytes.
			got = tf.originalBytes
		} else {
			got = tf.writtenBack.Bytes()
		}

		if string(want) == specialFileContentForSkippingDiff {
			return ""
		}

		diff := cmp.Diff(want, got)

		if diff == "" {
			return ""
		}

		return fmt.Sprintf(
			"unexpected result (-want, +got):\n%s\n",
			diff,
		)
	}

	return fmt.Sprintf("unable to find test file %q in tester.FS", name)
}

// DiffAll returns a human-readable diff for all files in the FS. If there are
// no diffs, an empty string is returned.
func (fsys *FS) DiffAll() string {
	fixtureFiles := lo.Keys(fsys.fixtures)
	sort.Strings(fixtureFiles)

	var result string
	for _, ff := range fixtureFiles {
		if fsys.fixtures[ff].isDir {
			continue
		}

		if diff := fsys.Diff(ff); diff != "" {
			result += fmt.Sprintf("\ndiff found for %q:\n", ff)
			result += diff
		}
	}

	return result
}

// registerTestFile registers a test file in the FS. If a file already existed at the
// given path, its entry in the FS will be replaced.
func (fsys *FS) registerTestFile(path string, tf *testFile) {
	if fsys.fixtures == nil {
		fsys.fixtures = make(map[string]*testFile)
	}

	fsys.fixtures[path] = tf
}

// addOriginalAndExpectedFilesAtPath adds an original test file from the
// underlying fs.FS. It will also load the corresponding expected file, which
// must be present. If there's an error reading the original or expected file
// from the underlying filesystem, an error is returned.
//
// If both files are read in successfully to the FS, a writeable buffer is also
// created for the file to observe what content is written back to the given
// path during testing.
func (fsys *FS) addOriginalAndExpectedFilesAtPath(path string) error {
	tf := new(testFile)
	tf.path = path
	tf.logger = fsys.logger

	if err := tf.loadOriginalFromUnderlyingFsys(fsys.underlying); err != nil {
		return fmt.Errorf("loading original file from existing fsys: %w", err)
	}

	if err := tf.loadExpectedFromUnderlyingFsys(fsys.underlying); err != nil {
		return fmt.Errorf("loading expected file from existing fsys: %w", err)
	}

	tf.writtenBack = new(bytes.Buffer)
	fsys.registerTestFile(path, tf)
	return nil
}

// addOnlyExpectedFileAtPath adds an expected test file from the underlying
// fs.FS. If there's an error reading the expected file from the underlying
// filesystem, an error is returned.
//
// This is intended for expected files with no corresponding original file, which
// are expected to be created during testing.
func (fsys *FS) addOnlyExpectedFileAtPath(expectedFilePath string) error {
	tf := new(testFile)
	tf.path = originalName(expectedFilePath)
	tf.logger = fsys.logger

	if err := tf.loadExpectedFromUnderlyingFsys(fsys.underlying); err != nil {
		return fmt.Errorf("loading expected file from existing fsys: %w", err)
	}

	tf.writtenBack = new(bytes.Buffer)
	fsys.registerTestFile(tf.path, tf)
	return nil
}

// registerDir registers a directory in the FS. It should be called for any
// intermediate directories in the file tree meant to be expressed by the FS.
func (fsys *FS) registerDir(path string) {
	tf := new(testFile)
	tf.isDir = true
	tf.path = path
	tf.logger = fsys.logger

	fsys.registerTestFile(path, tf)
}
