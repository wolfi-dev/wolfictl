package testerfs

import (
	"bytes"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
)

type testFile struct {
	path     string
	isDir    bool
	typ      fs.FileMode
	fileInfo fs.FileInfo

	// missingOriginal indicates whether the original file was missing from the
	// underlying filesystem (hopefully implying that the expected file does exist
	// nonetheless).
	missingOriginal bool

	originalBytes []byte

	// originalReader represents the contents of the "original" file as they were
	// initially observed in the test fixture data.
	originalReader *bytes.Reader

	// expectedRead represents the contents of the "expected" file as they were
	// initially observed in the test fixture data.
	expectedRead *bytes.Buffer

	// writtenBack represents the contents of the file as they were written back to
	// the tester filesystem during test execution. These bytes are retained
	// in-memory and then diffed against the expected file contents at the end of
	// the test by calling one of the tester FS's Diff methods.
	writtenBack *bytes.Buffer

	// writtenTo indicates whether the test has written back to the test file.
	writtenTo bool

	// writtenBackReader is a reader over the writtenBack buffer. It starts out nil
	// but gets created from the writtenBack buffer the first time the file is read
	// after having been written to.
	writtenBackReader *bytes.Reader

	logger *slog.Logger
}

// Name helps implement fs.DirEntry.
func (t *testFile) Name() string {
	if log := t.logger; log != nil {
		log.Debug("testFile: Name", "path", t.path)
	}

	return filepath.Base(t.path)
}

// IsDir helps implement fs.DirEntry.
func (t *testFile) IsDir() bool {
	if log := t.logger; log != nil {
		log.Debug("testFile: IsDir", "path", t.path)
	}

	return t.isDir
}

// Type helps implement fs.DirEntry.
func (t *testFile) Type() fs.FileMode {
	if log := t.logger; log != nil {
		log.Debug("testFile: Type", "path", t.path)
	}

	return t.typ
}

// Info helps implement fs.DirEntry.
func (t *testFile) Info() (fs.FileInfo, error) {
	if log := t.logger; log != nil {
		log.Debug("testFile: Info", "path", t.path)
	}

	return t.fileInfo, nil
}

// Stat helps implement fs.File.
func (t *testFile) Stat() (fs.FileInfo, error) {
	if log := t.logger; log != nil {
		log.Debug("testFile: Stat", "path", t.path)
	}

	return os.Stat(t.path)
}

// Read helps implement fs.File.
func (t *testFile) Read(p []byte) (int, error) {
	if log := t.logger; log != nil {
		log.Debug("testFile: Read", "path", t.path, "writtenTo", t.writtenTo)
	}

	// If the test has written back to the tester FS, read
	// from that instead.
	if t.writtenTo {
		if t.writtenBackReader == nil {
			t.writtenBackReader = bytes.NewReader(t.writtenBack.Bytes())
		}

		return t.writtenBackReader.Read(p)
	}

	return t.originalReader.Read(p)
}

// Close helps implement fs.File. For this type, it's a no-op.
func (t *testFile) Close() error {
	if log := t.logger; log != nil {
		log.Debug("testFile: Close", "path", t.path)
	}

	return nil
}

// Write helps implement rwfs.File.
func (t *testFile) Write(p []byte) (n int, err error) {
	if log := t.logger; log != nil {
		log.Debug("testFile: Write", "path", t.path)
	}

	t.writtenTo = true

	n, err = t.writtenBack.Write(p)

	t.writtenBackReader = bytes.NewReader(t.writtenBack.Bytes())

	return n, err
}

// loadOriginalFromExistingFsys loads the original file from the underlying
// filesystem into the FS (in-memory).
func (t *testFile) loadOriginalFromUnderlyingFsys(underlyingFsys fs.FS) error {
	originalBytes, err := fs.ReadFile(underlyingFsys, t.path)
	if err != nil {
		return fmt.Errorf("reading 'original' file from underlying filesystem: %w", err)
	}

	stat, err := fs.Stat(underlyingFsys, t.path)
	if err != nil {
		return fmt.Errorf("statting 'original' file from underlying filesystem: %w", err)
	}
	t.fileInfo = stat
	t.typ = stat.Mode()

	t.originalBytes = originalBytes

	forBuf := make([]byte, len(originalBytes))
	copy(forBuf, originalBytes)
	t.originalReader = bytes.NewReader(forBuf)

	return nil
}

// loadExpectedFromExistingFsys loads the expected file from the underlying
// filesystem into the FS (in-memory).
func (t *testFile) loadExpectedFromUnderlyingFsys(underlying fs.FS) error {
	expectedFile := expectedName(t.path)
	expectedBytes, err := fs.ReadFile(underlying, expectedFile)
	if err != nil {
		return fmt.Errorf("reading 'expected' file from underlying filesystem: %w", err)
	}

	t.expectedRead = bytes.NewBuffer(expectedBytes)

	return nil
}
