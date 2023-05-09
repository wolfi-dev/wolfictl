package tester

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
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

var expectedSuffixWithYAML = expectedSuffix + ".yaml"

var _ rwfs.FS = (*FS)(nil)

type FS struct {
	rootDir  string
	fixtures map[string]*testFile
}

func NewFSWithRoot(root string, fixtures ...string) (*FS, error) {
	realDirFS := os.DirFS(root)
	testerFS := new(FS)
	testerFS.rootDir = root

	testerFS.addDir(".")

	for _, f := range fixtures {
		stat, err := fs.Stat(realDirFS, f)
		if err != nil {
			return nil, fmt.Errorf("unable to stat file %q: %w", f, err)
		}

		if stat.IsDir() {
			err := fs.WalkDir(realDirFS, f, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.Type().IsDir() {
					testerFS.addDir(path)
					return nil
				}

				if d.Type().IsRegular() {
					if strings.HasSuffix(path, expectedSuffixWithYAML) {
						// this is a special file for this tester.FS! Skip.
						return nil
					}

					err := testerFS.addFixtureFileFromOS(path)
					if err != nil {
						return fmt.Errorf("unable to create new tester.FS: %w", err)
					}
				}

				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("unable to walk fixture directory %q: %w", f, err)
			}

			continue
		}

		err = testerFS.addFixtureFileFromOS(f)
		if err != nil {
			return nil, fmt.Errorf("unable to add fixture file %q to new tester.FS: %w", f, err)
		}
	}

	return testerFS, nil
}

func NewFS(fixtures ...string) (*FS, error) {
	return NewFSWithRoot(".", fixtures...)
}

func expectedName(original string) string {
	dir, file := filepath.Split(original)
	parts := strings.SplitN(file, ".", 2)

	expectedFile := strings.Join([]string{parts[0] + expectedSuffix, parts[1]}, ".")
	return filepath.Join(dir, expectedFile)
}

func (fsys *FS) Create(name string) (rwfs.File, error) {
	tf := new(testFile)
	tf.path = name

	err := tf.loadExpected(fsys)
	if err != nil {
		return nil, err
	}

	tf.writtenBack = new(bytes.Buffer)

	fsys.addTestFile(name, tf)

	return tf, nil
}

func (fsys *FS) Open(name string) (fs.File, error) {
	if f, ok := fsys.fixtures[name]; ok {
		return f, nil
	}

	return nil, os.ErrNotExist
}

func (fsys *FS) OpenAsWritable(name string) (rwfs.File, error) {
	if f, ok := fsys.fixtures[name]; ok {
		return f, nil
	}

	return nil, os.ErrNotExist
}

func (fsys *FS) Truncate(string, int64) error {
	// TODO: decide if there's a reason for anything but a no-op
	return nil
}

func (fsys *FS) Diff(name string) string {
	if tf, ok := fsys.fixtures[name]; ok {
		want := tf.expectedRead
		got := tf.writtenBack

		if want.String() == specialFileContentForSkippingDiff {
			return ""
		}

		diff := cmp.Diff(want.Bytes(), got.Bytes())

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

func (fsys *FS) addTestFile(path string, tf *testFile) {
	if fsys.fixtures == nil {
		fsys.fixtures = make(map[string]*testFile)
	}

	fsys.fixtures[path] = tf
}

func (fsys *FS) addFixtureFileFromOS(path string) error {
	tf := new(testFile)
	tf.path = path

	err := tf.loadOriginal(fsys)
	if err != nil {
		return err
	}

	err = tf.loadExpected(fsys)
	if err != nil {
		return err
	}

	tf.writtenBack = new(bytes.Buffer)

	fsys.addTestFile(path, tf)

	return nil
}

func (fsys *FS) readPath(path string) ([]byte, error) {
	effectivePath := filepath.Join(fsys.rootDir, path)
	return os.ReadFile(effectivePath)
}

func (fsys *FS) addDir(path string) {
	// For dirs, we'll punt to the real os FS.

	tf := new(testFile)
	tf.isDir = true
	tf.path = path

	fsys.addTestFile(path, tf)
}

type testFile struct {
	path                                    string
	isDir                                   bool
	originalBytes                           []byte
	readCompleted                           bool
	originalRead, expectedRead, writtenBack *bytes.Buffer
}

func (t *testFile) ReadDir(_ int) ([]fs.DirEntry, error) {
	if !t.isDir {
		return nil, fmt.Errorf("not a directory")
	}

	dirEntries, err := os.ReadDir(t.path)
	if err != nil {
		return nil, err
	}

	filteredDirEntries := lo.Filter(dirEntries, func(e os.DirEntry, _ int) bool {
		return !strings.HasSuffix(e.Name(), expectedSuffixWithYAML)
	})

	return filteredDirEntries, nil
}

func (t *testFile) Stat() (fs.FileInfo, error) {
	return os.Stat(t.path)
}

func (t *testFile) Read(p []byte) (int, error) {
	// We need to reset the t.originalRead buffer if it's already been read fully.
	if t.readCompleted {
		b := make([]byte, len(t.originalBytes))
		copy(b, t.originalBytes)
		t.originalRead = bytes.NewBuffer(b)

		t.readCompleted = false
	}

	n, err := t.originalRead.Read(p)
	if err != nil && errors.Is(err, io.EOF) {
		t.readCompleted = true
	}

	return n, err
}

func (t *testFile) Close() error {
	return nil
}

func (t *testFile) Write(p []byte) (n int, err error) {
	return t.writtenBack.Write(p)
}

func (t *testFile) loadOriginal(fsys *FS) error {
	originalBytes, err := fsys.readPath(t.path)
	if err != nil {
		return fmt.Errorf("unable to load fixture %q into tester.FS: %w", t.path, err)
	}

	t.originalBytes = originalBytes

	forBuf := make([]byte, len(originalBytes))
	copy(forBuf, originalBytes)
	t.originalRead = bytes.NewBuffer(forBuf)

	return nil
}

func (t *testFile) loadExpected(fsys *FS) error {
	expectedFile := expectedName(t.path)
	expectedBytes, err := fsys.readPath(expectedFile)
	if err != nil {
		return fmt.Errorf("unable to load fixture %q into tester.FS: no expected file %q: %w", t.path, expectedFile, err)
	}

	t.expectedRead = bytes.NewBuffer(expectedBytes)

	return nil
}
