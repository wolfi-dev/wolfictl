package dag

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewPackages(t *testing.T) {
	// for now, just a simple test that the loaded info is correct
	testdir := "testdata/complex"
	pkgs, err := NewPackages(context.Background(), os.DirFS(testdir), testdir, "")
	require.NoError(t, err)

	// should have named packages that match what is in the files and *not* the filenames
	expectedPackages := []string{"one", "two", "three-other"}
	sort.StringSlice(expectedPackages).Sort()
	require.Equal(t, expectedPackages, pkgs.PackageNames())

	// check that the configs for each target are correct

	// one should have two distinct versions
	configOne := pkgs.Config("one", true)
	require.Len(t, configOne, 2)
	for _, c := range configOne {
		require.Equal(t, "one", c.Package.Name)
	}
	require.Equal(t, "1.2.3", configOne[0].Package.Version)
	require.Equal(t, "1.2.8", configOne[1].Package.Version)
	require.Equal(t, configOne[0].Version(), fmt.Sprintf("%s-r%d", configOne[0].Package.Version, configOne[0].Package.Epoch))
	require.Equal(t, configOne[1].Version(), fmt.Sprintf("%s-r%d", configOne[1].Package.Version, configOne[1].Package.Epoch))
	require.Equal(t, configOne[0].Name(), configOne[0].Package.Name)
	require.Equal(t, configOne[1].Name(), configOne[1].Package.Name)
	require.Equal(t, filepath.Join(testdir, "one.yaml"), configOne[0].Path)
	require.Equal(t, filepath.Join(testdir, "one-dupl.yaml"), configOne[1].Path)

	// two should have one version
	configTwo := pkgs.Config("two", true)
	require.Len(t, configTwo, 1)
	require.Equal(t, "4.5.6", configTwo[0].Package.Version)
	require.Equal(t, "two", configTwo[0].Package.Name)
	require.Equal(t, configTwo[0].Version(), fmt.Sprintf("%s-r%d", configTwo[0].Package.Version, configTwo[0].Package.Epoch))
	require.Equal(t, configTwo[0].Name(), configTwo[0].Package.Name)
	require.Equal(t, filepath.Join(testdir, "two.yaml"), configTwo[0].Path)

	// three should have one version
	configThree := pkgs.Config("three-other", true)
	require.Len(t, configThree, 1)
	require.Equal(t, "7.8.9", configThree[0].Package.Version)
	require.Equal(t, "three-other", configThree[0].Package.Name)
	require.Equal(t, configThree[0].Version(), fmt.Sprintf("%s-r%d", configThree[0].Package.Version, configThree[0].Package.Epoch))
	require.Equal(t, configThree[0].Name(), configThree[0].Package.Name)
	require.Equal(t, filepath.Join(testdir, "three.yaml"), configThree[0].Path)

	// check that we can get by provides as well
	configTwoProvides := pkgs.Config("two-provides-explicit", false)
	require.Len(t, configTwoProvides, 1)
	require.Equal(t, "two-provides-explicit", configTwoProvides[0].Name())
	require.Equal(t, "10.11.12", configTwoProvides[0].Version())
	require.Equal(t, configTwo[0].Configuration, configTwoProvides[0].Configuration)

	configTwoProvidesImplicit := pkgs.Config("two-provides-implicit", false)
	require.Len(t, configTwoProvidesImplicit, 1)
	require.Equal(t, "two-provides-implicit", configTwoProvidesImplicit[0].Name())
	require.Equal(t, configTwo[0].Version(), configTwoProvidesImplicit[0].Version())
	require.Equal(t, configTwo[0].Configuration, configTwoProvidesImplicit[0].Configuration)

	// check that we can get by subpackage as well
	configOneSub := pkgs.Config("one-sub1", false)
	require.Equal(t, "one-sub1", configOneSub[0].Name())
	require.Equal(t, configOne[0].Version(), configOneSub[0].Version())
	require.Equal(t, configOne[0].Configuration, configOneSub[0].Configuration)
}
