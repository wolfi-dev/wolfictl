package dag

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewPackages(t *testing.T) {
	ctx := context.Background()

	testdir := "testdata/multiple"
	pkgs, err := NewPackages(ctx, os.DirFS(testdir), testdir, "")
	require.NoError(t, err)

	t.Run("loads data correctly", func(t *testing.T) {
		if l := len(pkgs.packages); l != 3 {
			t.Errorf("expected 3 packages to be loaded but got %d", l)
		}
	})

	t.Run("packages field map values", func(t *testing.T) {
		for name, cfgs := range pkgs.packages {
			if l := len(cfgs); l != 1 {
				t.Errorf("should all only have 1 configuration, but package name %q had %d configurations", name, l)
			}
		}
	})

	t.Run("multiple configurations using the same package name", func(t *testing.T) {
		testdir = "testdata/duplicate"
		pkgs, err = NewPackages(ctx, os.DirFS(testdir), testdir, "")
		if err == nil {
			t.Error("should yield an error but got nil")
		}
	})
}
