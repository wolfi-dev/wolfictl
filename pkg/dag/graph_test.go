package dag

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testDir = "testdata"

func TestNewGraph(t *testing.T) {
	t.Run("does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			_, err := NewGraph(os.DirFS(testDir), testDir)
			require.NoError(t, err)
		})
	})
}
