package advisory

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	advisoryconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/advisory"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func TestBuildDatabase(t *testing.T) {
	advisoryFsys := rwos.DirFS("./testdata/db/advisories")
	advisoryCfgs, err := advisoryconfigs.NewIndex(advisoryFsys)
	require.NoError(t, err)

	opts := BuildDatabaseOptions{
		AdvisoryCfgs: advisoryCfgs,
	}

	database, err := BuildDatabase(opts)
	require.NoError(t, err)

	expectedDatabase, err := os.ReadFile("./testdata/db/security.json")
	require.NoError(t, err)

	if diff := cmp.Diff(expectedDatabase, database); diff != "" {
		t.Errorf("BuildDatabase() produced an unexpected database (-want +got):\n%s", diff)
	}
}
