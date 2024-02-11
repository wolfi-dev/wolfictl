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
