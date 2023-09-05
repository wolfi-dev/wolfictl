package v2

import (
	"io/fs"

	"github.com/wolfi-dev/wolfictl/pkg/configs"
	"github.com/wolfi-dev/wolfictl/pkg/configs/rwfs"
)

func NewIndex(fsys rwfs.FS) (*configs.Index[Document], error) {
	return configs.NewIndex[Document](fsys, newConfigurationDecodeFunc(fsys))
}

func NewIndexFromPaths(fsys rwfs.FS, paths ...string) (*configs.Index[Document], error) {
	return configs.NewIndexFromPaths[Document](fsys, newConfigurationDecodeFunc(fsys), paths...)
}

func newConfigurationDecodeFunc(fsys fs.FS) func(string) (*Document, error) {
	return func(path string) (*Document, error) {
		file, err := fsys.Open(path)
		if err != nil {
			return nil, err
		}

		return decodeDocument(file)
	}
}
