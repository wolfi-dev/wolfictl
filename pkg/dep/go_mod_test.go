package dep

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_GetStrategy_Go(t *testing.T) {
	gs, err := GetStrategy("testdata/rebase-a")
	require.NoError(t, err, "should be go.mod strategy")
	require.Equal(t, gs.LockFileName(), "go.mod", "should be go.mod strategy")
}

func Test_GoStrategy_Rebase(t *testing.T) {
	gs, err := GetStrategy("testdata/rebase-a")
	require.NoError(t, err, "should be go.mod strategy")
	require.Equal(t, gs.LockFileName(), "go.mod", "should be go.mod strategy")

	err = gs.Rebase("testdata/rebase-a/go.mod", "testdata/rebase-a/go.mod.local", "testdata/rebase-a/go.mod.local.new")
	require.NoError(t, err, "the rebase is required to complete successfully")
}
