package build

import (
	"context"
	"testing"

	"chainguard.dev/melange/pkg/config"
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

	index, err := NewIndexFromPaths(context.Background(), fsys, testfiles...)
	require.NoError(t, err)

	const modifiedPackageName = "foobar"

	packageSectionUpdater := NewPackageSectionUpdater(func(cfg config.Configuration) (config.Package, error) {
		p := cfg.Package
		p.Name = modifiedPackageName
		return p, nil
	})

	s := index.Select().WhereName("cheese")
	err = s.Update(context.Background(), packageSectionUpdater)
	require.NoError(t, err)

	if diff := fsys.DiffAll(); diff != "" {
		t.Errorf("unexpected file modification results (-want, +got):\n%s", diff)
	}
}

func TestBuildConfigsIndexUpdatePipelines(t *testing.T) {
	testfiles := []string{
		"config-1.yaml",
		"config-3.yaml",
	}

	fsys, err := tester.NewFSWithRoot(
		"testdata/rwfs-index",
		testfiles...,
	)
	require.NoError(t, err)

	index, err := NewIndexFromPaths(context.Background(), fsys, testfiles...)
	require.NoError(t, err)

	pipelineSectionUpdater := NewPipelineSectionUpdater(func(cfg config.Configuration) ([]config.Pipeline, error) {
		pipes := cfg.Pipeline
		pipes[1].With["deps"] = "golang/go@v1.21 k8s.io/api@1.29"
		return pipes, nil
	})

	s := index.Select().WhereName("blah")
	err = s.Update(context.Background(), pipelineSectionUpdater)
	require.NoError(t, err)

	if diff := fsys.DiffAll(); diff != "" {
		t.Errorf("unexpected file modification results (-want, +got):\n%s", diff)
	}
}

func TestBuildConfigsIndexUpdateSubpackages(t *testing.T) {
	testfiles := []string{
		"config-4.yaml",
	}

	fsys, err := tester.NewFSWithRoot(
		"testdata/rwfs-index",
		testfiles...,
	)
	require.NoError(t, err)

	index, err := NewIndexFromPaths(context.Background(), fsys, testfiles...)
	require.NoError(t, err)

	const modifiedSubPackageName = "foobar"
	subpackagesSectionUpdater := NewSubpackagesSectionUpdater(func(cfg config.Configuration) ([]config.Subpackage, error) {
		subpackages := cfg.Subpackages
		subpackages[0].Name = modifiedSubPackageName
		return subpackages, nil
	})

	s := index.Select().WhereName("blah")
	err = s.Update(context.Background(), subpackagesSectionUpdater)
	require.NoError(t, err)

	if diff := fsys.DiffAll(); diff != "" {
		t.Errorf("unexpected file modification results (-want, +got):\n%s", diff)
	}
}
