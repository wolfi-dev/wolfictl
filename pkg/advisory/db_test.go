package advisory

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	advisoryconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v1"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func TestBuildDatabase(t *testing.T) {
	cases := []struct {
		name                   string
		advisoryDirs           []string
		pathToExpectedDatabase string
		errorAssertion         assert.ErrorAssertionFunc
	}{
		{
			name: "single advisories dir",
			advisoryDirs: []string{
				"./testdata/db/advisories",
			},
			pathToExpectedDatabase: "./testdata/db/security.json",
			errorAssertion:         assert.NoError,
		},
		{
			name: "multiple advisories dirs",
			advisoryDirs: []string{
				"./testdata/db/advisories",
				"./testdata/db/other-advisories",
			},
			pathToExpectedDatabase: "./testdata/db/security-multiple.json",
			errorAssertion:         assert.NoError,
		},
		{
			name: "use a dir with no adv data",
			advisoryDirs: []string{
				"./testdata/db/advisories",
				"./testdata/db/advisories-empty",
			},
			pathToExpectedDatabase: "",
			errorAssertion: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, ErrNoPackageSecurityData)
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			indices := make([]*configs.Index[advisoryconfigs.Document], 0, len(tt.advisoryDirs))
			for _, dir := range tt.advisoryDirs {
				advisoryFsys := rwos.DirFS(dir)
				advisoryCfgs, err := advisoryconfigs.NewIndex(advisoryFsys)
				require.NoError(t, err)
				indices = append(indices, advisoryCfgs)
			}

			opts := BuildDatabaseOptions{
				AdvisoryCfgIndices: indices,
				URLPrefix:          "https://packages.wolfi.dev",
				Archs:              []string{"x86_64"},
				Repo:               "os",
			}

			database, err := BuildDatabase(opts)
			tt.errorAssertion(t, err)

			if p := tt.pathToExpectedDatabase; p != "" {
				expectedDatabase, err := os.ReadFile(p)
				require.NoError(t, err)

				if diff := cmp.Diff(expectedDatabase, database); diff != "" {
					t.Errorf("BuildDatabase() produced an unexpected database (-want +got):\n%s", diff)
				}
			}
		})
	}
}
