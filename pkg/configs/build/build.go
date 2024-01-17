package build

import (
	"context"
	"io/fs"

	"chainguard.dev/melange/pkg/config"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	"github.com/wolfi-dev/wolfictl/pkg/configs/rwfs"
)

func NewIndex(fsys rwfs.FS) (*configs.Index[config.Configuration], error) {
	return configs.NewIndex[config.Configuration](fsys, newConfigurationDecodeFunc(fsys))
}

func NewIndexFromPaths(fsys rwfs.FS, paths ...string) (*configs.Index[config.Configuration], error) {
	return configs.NewIndexFromPaths[config.Configuration](fsys, newConfigurationDecodeFunc(fsys), paths...)
}

func newConfigurationDecodeFunc(fsys fs.FS) func(string) (*config.Configuration, error) {
	return func(path string) (*config.Configuration, error) {
		ctx := context.Background()
		return config.ParseConfiguration(ctx, path, config.WithFS(fsys))
	}
}
