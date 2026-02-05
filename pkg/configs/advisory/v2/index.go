package v2

import (
	"context"
	"io/fs"

	v2 "github.com/chainguard-dev/advisory-schema/pkg/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	"github.com/wolfi-dev/wolfictl/pkg/configs/rwfs"
)

func NewIndex(ctx context.Context, fsys rwfs.FS) (*configs.Index[v2.Document], error) {
	return configs.NewIndex[v2.Document](ctx, fsys, newConfigurationDecodeFunc(fsys))
}

func NewIndexFromPaths(ctx context.Context, fsys rwfs.FS, paths ...string) (*configs.Index[v2.Document], error) {
	return configs.NewIndexFromPaths[v2.Document](ctx, fsys, newConfigurationDecodeFunc(fsys), paths...)
}

func newConfigurationDecodeFunc(fsys fs.FS) func(context.Context, string) (*v2.Document, error) {
	return func(_ context.Context, path string) (*v2.Document, error) {
		file, err := fsys.Open(path)
		if err != nil {
			return nil, err
		}

		return v2.DecodeDocument(file)
	}
}
