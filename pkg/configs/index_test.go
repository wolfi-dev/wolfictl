package configs

import (
	"context"
	"testing"

	"chainguard.dev/melange/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func TestNewIndex(t *testing.T) {
	ctx := context.Background()
	fsys := rwos.DirFS("testdata/index-1")

	index, err := NewIndex[config.Configuration](ctx, fsys, func(ctx context.Context, path string) (*config.Configuration, error) {
		return config.ParseConfiguration(ctx, path, config.WithFS(fsys))
	})
	require.NoError(t, err)

	t.Run("includes real configs", func(t *testing.T) {
		assert.Contains(t, index.paths, "config-1.yaml")
		assert.Contains(t, index.paths, "config-2.yaml")
	})

	t.Run("skips configs in subdirectories", func(t *testing.T) {
		assert.NotContains(t, index.paths, "subdir/not-a-config.yaml")
	})

	t.Run("skips hidden files", func(t *testing.T) {
		assert.NotContains(t, index.paths, ".not-a-config.yaml")
	})
}

func TestRemove(t *testing.T) {
	ctx := context.Background()
	fsys := rwos.DirFS("testdata/index-1")

	index, err := NewIndex[config.Configuration](ctx, fsys, func(ctx context.Context, path string) (*config.Configuration, error) {
		return config.ParseConfiguration(ctx, path, config.WithFS(fsys))
	})
	require.NoError(t, err)

	name := "config-new"
	filename := name + ".advisories.yaml"

	err = index.Create(ctx, filename, config.Configuration{
		Package: config.Package{
			Name:    name,
			Version: "1.0.0",
		},
	})
	require.NoError(t, err)

	_, err = index.Select().WhereName(name).First()
	require.NoError(t, err)

	t.Run("removes a config", func(t *testing.T) {
		err := index.Remove(filename)
		require.NoError(t, err)

		assert.NotContains(t, index.paths, filename)
	})

	t.Run("ensure the config is removed", func(t *testing.T) {
		_, err := index.Select().WhereName(name).First()
		require.Error(t, err)
	})
}
