package v2

import (
	"context"
	"io/fs"

	"github.com/wolfi-dev/wolfictl/pkg/configs"
	"github.com/wolfi-dev/wolfictl/pkg/configs/rwfs"
)

func NewIndex(ctx context.Context, fsys rwfs.FS) (*configs.Index[Document], error) {
	return configs.NewIndex[Document](ctx, fsys, newConfigurationDecodeFunc(fsys))
}

func NewIndexFromPaths(ctx context.Context, fsys rwfs.FS, paths ...string) (*configs.Index[Document], error) {
	return configs.NewIndexFromPaths[Document](ctx, fsys, newConfigurationDecodeFunc(fsys), paths...)
}

func newConfigurationDecodeFunc(fsys fs.FS) func(context.Context, string) (*Document, error) {
	return func(_ context.Context, path string) (*Document, error) {
		file, err := fsys.Open(path)
		if err != nil {
			return nil, err
		}

		return DecodeDocument(file)
	}
}
