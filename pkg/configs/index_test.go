package configs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func TestNewIndex(t *testing.T) {
	t.Run("skips configs in subdirectories", func(t *testing.T) {
		fsys := rwos.DirFS("testdata/index-1")

		index, err := NewIndex(fsys)
		require.NoError(t, err)

		assert.Contains(t, index.paths, "config-1.yaml")
		assert.NotContains(t, index.paths, "subdir/not-a-config.yaml")
	})
}
