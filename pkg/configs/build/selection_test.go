package build

import (
	"testing"

	"chainguard.dev/melange/pkg/build"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func TestSelection(t *testing.T) {
	fsys := rwos.DirFS("testdata/index-1")

	index, err := configs.NewIndex[build.Configuration](fsys, newConfigurationDecodeFunc(fsys))
	require.NoError(t, err)

	s := index.Select()

	t.Run("Select", func(t *testing.T) {
		assert.Equal(t, 2, s.Len())
	})

	t.Run("WhereName", func(t *testing.T) {
		cheeseSelection := s.WhereName("cheese")
		require.Equal(t, 1, cheeseSelection.Len())
		assert.Equal(t, "cheese", cheeseSelection.Entries()[0].Configuration().Package.Name)

		nonexistentSelection := s.WhereName("not-a-real-name!")
		assert.Equal(t, 0, nonexistentSelection.Len())
	})

	t.Run("WhereFilePath", func(t *testing.T) {
		cheeseSelection := s.WhereFilePath("config-2.yaml")
		require.Equal(t, 1, cheeseSelection.Len())
		assert.Equal(t, "cheese", cheeseSelection.Entries()[0].Configuration().Package.Name)

		nonexistentSelection := s.WhereFilePath("not-a-real-path!")
		assert.Equal(t, 0, nonexistentSelection.Len())
	})
}
