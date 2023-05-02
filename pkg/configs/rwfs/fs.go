package rwfs

import (
	"io"
	"io/fs"
)

type FS interface {
	Open(name string) (fs.File, error)
	OpenAsWritable(name string) (File, error)
	Truncate(name string, size int64) error
	Create(name string) (File, error)
}

type File interface {
	fs.File
	io.Writer
}
