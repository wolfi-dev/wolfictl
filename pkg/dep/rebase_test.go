package dep

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_HighLevelRebase(t *testing.T) {
	err := Rebase("testdata/rebase-b")
	require.NoError(t, err, "rebase operation must succeed")
}

func Test_HighLevelUpdateChecksums(t *testing.T) {
	err := UpdateChecksums("testdata/update-checksums")
	require.NoError(t, err, "update checksums operation must succeed")
}
