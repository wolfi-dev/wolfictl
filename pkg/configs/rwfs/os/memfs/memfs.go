package memfs

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"sync"
	"time"

	"github.com/wolfi-dev/wolfictl/pkg/configs/rwfs"
)

var _ rwfs.FS = (*memWriteFS)(nil)

// memWriteFS is a file system that reads file content initially from the
// provided fs.FS, but all writes and subsequent reads on files are based on
// in-memory representations of those files, such that a memWriteFS will never
// modify files on disk. This is especially useful for testing scenarios where
// you have test fixture files but you want to ensure they aren't actually
// modified during the test.
type memWriteFS struct {
	underlying fs.FS                  // The underlying file system
	data       map[string]interface{} // Values can be *bytes.Buffer (for files) or memDir (for directories)
	mu         sync.RWMutex
}

// New creates and returns a new memWriteFS based on the provided fs.FS.
func New(underlying fs.FS) rwfs.FS {
	return &memWriteFS{
		underlying: underlying,
		data:       make(map[string]interface{}),
	}
}

func (m *memWriteFS) Open(name string) (fs.File, error) {
	return m.openInternal(name, false)
}

func (m *memWriteFS) OpenAsWritable(name string) (rwfs.File, error) {
	return m.openInternal(name, true)
}

func (m *memWriteFS) openInternal(name string, writable bool) (rwfs.File, error) {
	m.mu.RLock()
	data, exists := m.data[name]
	m.mu.RUnlock()

	if exists {
		switch v := data.(type) {
		case *bytes.Buffer:
			return &memFile{
				name:     name,
				buf:      v,
				reader:   bytes.NewReader(v.Bytes()),
				writable: writable,
			}, nil
		case memDir:
			return &memDirFile{name: name, entries: v.entries, pos: 0}, nil
		default:
			return nil, errors.New("unknown data type in memory")
		}
	}

	// Open from the underlying FS
	file, err := m.underlying.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if stat.IsDir() {
		entries, err := fs.ReadDir(m.underlying, name)
		if err != nil {
			return nil, err
		}

		// Store directory entries in memory
		memDir := memDir{entries: entries}
		m.mu.Lock()
		m.data[name] = memDir
		m.mu.Unlock()

		return &memDirFile{name: name, entries: entries, pos: 0}, nil
	}

	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, file)
	if err != nil {
		return nil, err
	}

	// Store the file content in memory
	m.mu.Lock()
	m.data[name] = buf
	m.mu.Unlock()

	return &memFile{
		name:     name,
		buf:      buf,
		reader:   bytes.NewReader(buf.Bytes()),
		writable: writable,
	}, nil
}

func (m *memWriteFS) Truncate(name string, size int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, exists := m.data[name]
	if !exists {
		return errors.New("file not found")
	}

	if data, ok := data.(*bytes.Buffer); ok {
		data.Truncate(int(size))
	}

	return nil
}

func (m *memWriteFS) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.data, name)
	return nil
}

func (m *memWriteFS) Create(name string) (rwfs.File, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if the name corresponds to an existing directory
	if _, ok := m.data[name].(memDir); ok {
		return nil, &fs.PathError{Op: "create", Path: name, Err: errors.New("is a directory")}
	}

	// Create or overwrite the file in memory
	buf := new(bytes.Buffer)
	m.data[name] = buf

	return &memFile{
		name:     name,
		buf:      buf,
		writable: true,
	}, nil
}

type memFile struct {
	name     string
	buf      *bytes.Buffer
	reader   *bytes.Reader
	writable bool
}

func (f *memFile) Read(p []byte) (n int, err error) {
	return f.reader.Read(p)
}

func (f *memFile) Write(p []byte) (n int, err error) {
	if !f.writable {
		return 0, errors.New("file not opened for writing")
	}
	n, err = f.buf.Write(p)
	f.reader = bytes.NewReader(f.buf.Bytes()) // Reset reader with updated buffer content
	return n, err
}

func (f *memFile) Close() error {
	_, err := f.reader.Seek(0, io.SeekStart)
	return err
}

func (f *memFile) Name() string {
	return f.name
}

func (f *memFile) Stat() (fs.FileInfo, error) {
	return &memFileInfo{
		name:  f.name,
		size:  int64(f.buf.Len()),
		isDir: false,
	}, nil
}

func (f *memFile) Seek(offset int64, whence int) (int64, error) {
	return f.reader.Seek(offset, whence)
}

type memFileInfo struct {
	name  string
	size  int64
	isDir bool
}

func (mfi *memFileInfo) Name() string       { return mfi.name }
func (mfi *memFileInfo) Size() int64        { return mfi.size }
func (mfi *memFileInfo) Mode() fs.FileMode  { return 0o644 }
func (mfi *memFileInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (mfi *memFileInfo) IsDir() bool        { return mfi.isDir }
func (mfi *memFileInfo) Sys() interface{}   { return nil }

type memDir struct {
	entries []fs.DirEntry
}

type memDirFile struct {
	name    string
	entries []fs.DirEntry
	pos     int
}

func (df *memDirFile) Read(_ []byte) (n int, err error) {
	return 0, errors.New("cannot read from directory")
}

func (df *memDirFile) Write(_ []byte) (n int, err error) {
	return 0, errors.New("cannot write to directory")
}

func (df *memDirFile) Close() error       { return nil }
func (df *memDirFile) Name() string       { return df.name }
func (df *memDirFile) Size() int64        { return 0 }
func (df *memDirFile) Mode() fs.FileMode  { return 0o644 }
func (df *memDirFile) ModTime() time.Time { return time.Unix(0, 0) }
func (df *memDirFile) IsDir() bool        { return true }
func (df *memDirFile) Sys() interface{}   { return nil }

func (df *memDirFile) Stat() (fs.FileInfo, error) {
	return &memFileInfo{
		name:  df.name,
		size:  0,
		isDir: true,
	}, nil
}

func (df *memDirFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if n <= 0 || n > len(df.entries)-df.pos {
		n = len(df.entries) - df.pos
	}
	entries := df.entries[df.pos : df.pos+n]
	df.pos += n
	return entries, nil
}
