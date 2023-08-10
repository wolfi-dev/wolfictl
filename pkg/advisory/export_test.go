package advisory

import (
	"io"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	advisoryconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v1"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func TestExportCSV(t *testing.T) {
	cases := []struct {
		name               string
		advisoryDirs       []string
		pathToExpectedData string
		errorAssertion     assert.ErrorAssertionFunc
	}{
		{
			name: "single advisories dir",
			advisoryDirs: []string{
				"./testdata/export/advisories",
			},
			pathToExpectedData: "./testdata/export/expected.csv",
			errorAssertion:     assert.NoError,
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

			opts := ExportOptions{
				AdvisoryCfgIndices: indices,
			}

			exported, err := ExportCSV(opts)
			tt.errorAssertion(t, err)

			exportedBytes, err := io.ReadAll(exported)
			require.NoError(t, err)

			if p := tt.pathToExpectedData; p != "" {
				expectedBytes, err := os.ReadFile(p)
				require.NoError(t, err)

				if diff := cmp.Diff(string(expectedBytes), string(exportedBytes)); diff != "" {
					t.Errorf("ExportCSV() produced unexpected data (-want +got):\n%s", diff)
				}
			}
		})
	}
}
