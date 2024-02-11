package advisory

import (
	"context"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func TestBuildSecurityDatabase(t *testing.T) {
	cases := []struct {
		name                   string
		advisoryDirs           []string
		pathToExpectedDatabase string
		errorAssertion         assert.ErrorAssertionFunc
	}{
		{
			name: "single advisories dir",
			advisoryDirs: []string{
				"./testdata/secdb/advisories",
			},
			pathToExpectedDatabase: "./testdata/secdb/security.json",
			errorAssertion:         assert.NoError,
		},
		{
			name: "multiple advisories dirs",
			advisoryDirs: []string{
				"./testdata/secdb/advisories",
				"./testdata/secdb/other-advisories",
			},
			pathToExpectedDatabase: "./testdata/secdb/security-multiple.json",
			errorAssertion:         assert.NoError,
		},
		{
			name: "use a dir with no adv data",
			advisoryDirs: []string{
				"./testdata/secdb/advisories",
				"./testdata/secdb/advisories-empty",
			},
			pathToExpectedDatabase: "",
			errorAssertion: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.Error(t, err) && assert.ErrorIs(t, err, ErrNoPackageSecurityData)
			},
		},
		{
			name: "package overlap between dirs",
			advisoryDirs: []string{
				"./testdata/secdb/advisories",
				"./testdata/secdb/advisories-with-package-overlap",
			},
			pathToExpectedDatabase: "",
			errorAssertion: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.Error(t, err) && assert.ErrorIs(t, err, ErrorPackageCollision)
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			indices := make([]*configs.Index[v2.Document], 0, len(tt.advisoryDirs))
			for _, dir := range tt.advisoryDirs {
				advisoryFsys := rwos.DirFS(dir)
				advisoryCfgs, err := v2.NewIndex(context.Background(), advisoryFsys)
				require.NoError(t, err)
				indices = append(indices, advisoryCfgs)
			}

			opts := BuildSecurityDatabaseOptions{
				AdvisoryDocIndices: indices,
				URLPrefix:          "https://packages.wolfi.dev",
				Archs:              []string{"x86_64"},
				Repo:               "os",
			}

			database, err := BuildSecurityDatabase(opts)
			tt.errorAssertion(t, err)

			if p := tt.pathToExpectedDatabase; p != "" {
				expectedDatabase, err := os.ReadFile(p)
				require.NoError(t, err)

				if diff := cmp.Diff(expectedDatabase, database); diff != "" {
					t.Errorf("BuildSecurityDatabase() produced an unexpected database (-want +got):\n%s", diff)
				}
			}
		})
	}
}
