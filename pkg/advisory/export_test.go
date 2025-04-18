package advisory

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	v2 "github.com/chainguard-dev/advisory-schema/pkg/advisory/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	adv2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func Test_ExportFuncs(t *testing.T) {
	const testdataDir = "./testdata/export/advisories"

	cases := []struct {
		name                string
		exportFuncUnderTest func(ExportOptions) (io.Reader, error)
		pathToExpectedData  string
	}{
		{
			name:                "csv",
			exportFuncUnderTest: ExportCSV,
			pathToExpectedData:  "./testdata/export/expected.csv",
		},
		{
			name:                "yaml",
			exportFuncUnderTest: ExportYAML,
			pathToExpectedData:  "./testdata/export/expected.yaml",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			advisoryFsys := rwos.DirFS(testdataDir)
			advisoryDocs, err := adv2.NewIndex(context.Background(), advisoryFsys)
			require.NoError(t, err)
			indices := []*configs.Index[v2.Document]{advisoryDocs}

			opts := ExportOptions{
				AdvisoryDocIndices: indices,
			}

			exported, err := tt.exportFuncUnderTest(opts)
			assert.NoError(t, err)

			exportedBytes, err := io.ReadAll(exported)
			require.NoError(t, err)

			if p := tt.pathToExpectedData; p != "" {
				expectedBytes, err := os.ReadFile(p)
				require.NoError(t, err)

				if diff := cmp.Diff(string(expectedBytes), string(exportedBytes)); diff != "" {
					t.Errorf("Export%s() produced unexpected data (-want +got):\n%s", strings.ToUpper(tt.name), diff)
				}
			}
		})
	}
}
