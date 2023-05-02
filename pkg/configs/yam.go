package configs

import (
	"io/fs"

	yamRWFS "github.com/chainguard-dev/yam/pkg/rwfs"
	"github.com/wolfi-dev/wolfictl/pkg/configs/rwfs"
)

type yamFsysAdapter struct {
	fsys rwfs.FS
}

func (fsys yamFsysAdapter) Open(name string) (fs.File, error) {
	return fsys.fsys.Open(name)
}

func (fsys yamFsysAdapter) OpenRW(name string) (yamRWFS.File, error) {
	return fsys.fsys.OpenAsWritable(name)
}

func (fsys yamFsysAdapter) Truncate(name string, size int64) error {
	return fsys.fsys.Truncate(name, size)
}
