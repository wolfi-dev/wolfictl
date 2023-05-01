package configs

import (
	"testing"

	"chainguard.dev/melange/pkg/build"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func TestNewIndex(t *testing.T) {
	fsys := rwos.DirFS("testdata/index-1")

	index, err := NewIndex[build.Configuration](fsys, func(path string) (*build.Configuration, error) {
		return build.ParseConfiguration(path, build.WithFS(fsys))
	})
	require.NoError(t, err)

	t.Run("includes real configs", func(t *testing.T) {
		assert.Contains(t, index.paths, "config-1.yaml")
	})

	t.Run("skips configs in subdirectories", func(t *testing.T) {
		assert.NotContains(t, index.paths, "subdir/not-a-config.yaml")
	})

	t.Run("skips hidden files", func(t *testing.T) {
		assert.NotContains(t, index.paths, ".not-a-config.yaml")
	})
}
