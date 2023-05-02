package build

import (
	"io/fs"

	"chainguard.dev/melange/pkg/build"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	"github.com/wolfi-dev/wolfictl/pkg/configs/rwfs"
)

func NewIndex(fsys rwfs.FS) (*configs.Index[build.Configuration], error) {
	return configs.NewIndex[build.Configuration](fsys, newConfigurationDecodeFunc(fsys))
}

func NewIndexFromPaths(fsys rwfs.FS, paths ...string) (*configs.Index[build.Configuration], error) {
	return configs.NewIndexFromPaths[build.Configuration](fsys, newConfigurationDecodeFunc(fsys), paths...)
}

func newConfigurationDecodeFunc(fsys fs.FS) func(string) (*build.Configuration, error) {
	return func(path string) (*build.Configuration, error) {
		return build.ParseConfiguration(path, build.WithFS(fsys))
	}
}
