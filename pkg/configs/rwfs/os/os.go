package os

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/wolfi-dev/wolfictl/pkg/configs/rwfs"
)

var DefaultFilePerm = fs.FileMode(0o0755)

type FS struct {
	rootDir string
}

var _ rwfs.FS = (*FS)(nil)

func (fsys FS) Open(name string) (fs.File, error) {
	p := fsys.fullPath(name)
	return os.Open(p)
}

func (fsys FS) OpenAsWritable(name string) (rwfs.File, error) {
	p := fsys.fullPath(name)
	return os.OpenFile(p, os.O_RDWR, DefaultFilePerm)
}

func (fsys FS) Truncate(name string, size int64) error {
	p := fsys.fullPath(name)
	return os.Truncate(p, size)
}

func (fsys FS) fullPath(name string) string {
	return filepath.Join(fsys.rootDir, name)
}

func DirFS(dir string) rwfs.FS {
	return FS{rootDir: dir}
}
