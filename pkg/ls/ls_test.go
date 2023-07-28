package ls

import (
	"testing"

	"chainguard.dev/melange/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	buildconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/build"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func TestList(t *testing.T) {
	cases := []struct {
		name               string
		distroDirs         []string
		includeSubpackages bool
		requestedPackages  []string
		template           string
		expectedResults    []string
		errorAssertion     assert.ErrorAssertionFunc
	}{
		{
			name: "package names",
			distroDirs: []string{
				"./testdata/buildconfigs",
			},
			expectedResults: []string{
				"acl",
				"aom",
				"apko",
			},
			errorAssertion: assert.NoError,
		},
		{
			name: "package and subpackage names",
			distroDirs: []string{
				"./testdata/buildconfigs",
			},
			includeSubpackages: true,
			expectedResults: []string{
				"acl",
				"acl-dev",
				"libacl1",
				"aom",
				"aom-dev",
				"aom-libs",
				"apko",
			},
			errorAssertion: assert.NoError,
		},
		{
			name: "specific package's subpackages",
			distroDirs: []string{
				"./testdata/buildconfigs",
			},
			includeSubpackages: true,
			requestedPackages:  []string{"aom"},
			expectedResults: []string{
				"aom",
				"aom-dev",
				"aom-libs",
			},
			errorAssertion: assert.NoError,
		},
		{
			name: "nonexistent package",
			distroDirs: []string{
				"./testdata/buildconfigs",
			},
			includeSubpackages: true,
			requestedPackages:  []string{"nonexistent"},
			errorAssertion:     assert.Error,
		},
		{
			name: "template (e.g. show pipeline's first step)",
			distroDirs: []string{
				"./testdata/buildconfigs",
			},
			expectedResults: []string{
				"fetch",
				"git-checkout",
				"git-checkout",
			},
			template:       "{{(index (.Pipeline) 0).Uses}}",
			errorAssertion: assert.NoError,
		},
		{
			name: "bad template",
			distroDirs: []string{
				"./testdata/buildconfigs",
			},
			template:       "{{.lsdjflksjfljslefjlsdkjflsdjfljdlfk}}",
			errorAssertion: assert.Error,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			indices := make([]*configs.Index[config.Configuration], 0, len(tt.distroDirs))
			for _, dir := range tt.distroDirs {
				distroFsys := rwos.DirFS(dir)
				buildCfgs, err := buildconfigs.NewIndex(distroFsys)
				require.NoError(t, err)
				indices = append(indices, buildCfgs)
			}

			opts := ListOptions{
				BuildCfgIndices:    indices,
				IncludeSubpackages: tt.includeSubpackages,
				RequestedPackages:  tt.requestedPackages,
				Template:           tt.template,
			}

			results, err := List(opts)
			tt.errorAssertion(t, err)

			assert.Equal(t, tt.expectedResults, results)
		})
	}
}
