package dep

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_HighLevelRebase(t *testing.T) {
	err := Rebase("testdata/rebase-b")
	require.NoError(t, err, "rebase operation must succeed")
}
