package build

import (
	"context"
	"io/fs"

	"chainguard.dev/melange/pkg/config"
	"github.com/chainguard-dev/clog"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	"github.com/wolfi-dev/wolfictl/pkg/configs/rwfs"
	"github.com/wolfi-dev/wolfictl/pkg/internal"
)

func NewIndex(ctx context.Context, fsys rwfs.FS) (*configs.Index[config.Configuration], error) {
	return configs.NewIndex[config.Configuration](ctx, fsys, newConfigurationDecodeFunc(fsys))
}

func NewIndexFromPaths(ctx context.Context, fsys rwfs.FS, paths ...string) (*configs.Index[config.Configuration], error) {
	return configs.NewIndexFromPaths[config.Configuration](ctx, fsys, newConfigurationDecodeFunc(fsys), paths...)
}

func newConfigurationDecodeFunc(fsys fs.FS) func(context.Context, string) (*config.Configuration, error) {
	return func(ctx context.Context, path string) (*config.Configuration, error) {
		ctx = clog.WithLogger(ctx, clog.NewLogger(internal.NopLogger()))
		return config.ParseConfiguration(ctx, path, config.WithFS(fsys))
	}
}
