package build

import (
	"testing"

	"chainguard.dev/melange/pkg/build"
	"github.com/stretchr/testify/require"
	"github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os/tester"
)

func TestBuildConfigsIndex(t *testing.T) {
	testfiles := []string{
		"config-1.yaml",
		"config-2.yaml",
	}

	fsys, err := tester.NewFSWithRoot(
		"testdata/rwfs-index",
		testfiles...,
	)
	require.NoError(t, err)

	index, err := NewIndexFromPaths(fsys, testfiles...)
	require.NoError(t, err)

	const modifiedPackageName = "foobar"

	packageSectionUpdater := NewPackageSectionUpdater(func(cfg build.Configuration) (build.Package, error) {
		p := cfg.Package
		p.Name = modifiedPackageName
		return p, nil
	})

	s := index.Select().WhereName("cheese")
	err = s.UpdateEntries(packageSectionUpdater)
	require.NoError(t, err)

	if diff := fsys.DiffAll(); diff != "" {
		t.Errorf("unexpected file modification results (-want, +got):\n%s", diff)
	}
}
