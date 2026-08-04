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
	pkgs, err := NewPackages(ctx, os.DirFS(testdir), testdir, nil)
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
		pkgs, err = NewPackages(ctx, os.DirFS(testdir), testdir, nil)
		if err == nil {
			t.Error("should yield an error but got nil")
		}
	})
}

func TestPackagesRepositoryPreservesSubpackageProviderPriority(t *testing.T) {
	ctx := context.Background()
	testdir := "testdata/provider-priority"

	pkgs, err := NewPackages(ctx, os.DirFS(testdir), testdir, nil)
	require.NoError(t, err)

	repo, err := pkgs.Repository("x86_64")
	require.NoError(t, err)

	priorities := map[string]uint64{}
	for _, pkg := range repo.Packages() {
		priorities[pkg.Name] = pkg.ProviderPriority
	}

	require.Equal(t, map[string]uint64{
		"gdal":            0,
		"gdal-py3.13-dev": 313,
		"gdal-compat":     0,
	}, priorities)
}

func TestParseProviderPriority(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint64
		wantErr string
	}{
		{name: "empty", input: "", want: 0},
		{name: "positive", input: "313", want: 313},
		{name: "negative clamps to zero", input: "-1", want: 0},
		{name: "non-numeric", input: "invalid", wantErr: `parsing "invalid"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseProviderPriority(tt.input)

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				require.Zero(t, got)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// buildDeps returns the resolved environment.contents.packages for an origin
// package, which is the only thing melange's Compile step affects.
func buildDeps(t *testing.T, p *Packages, name string) []string {
	t.Helper()
	cfgs := p.Config(name, true)
	require.Len(t, cfgs, 1)
	return cfgs[0].Environment.Contents.Packages
}

func TestNewPackagesWithCompileOnly(t *testing.T) {
	ctx := context.Background()
	testdir := "testdata/multiple"

	// environment.contents.packages as written in the YAML, before the `uses:`
	// pipelines are resolved into additional build dependencies.
	const (
		oneLiteral = 4
		twoLiteral = 5
	)

	all, err := NewPackages(ctx, os.DirFS(testdir), testdir, nil)
	require.NoError(t, err)

	// Both definitions use `uses:` pipelines, so compiling must grow both lists.
	// Without this the test below could pass for the wrong reason.
	require.Greater(t, len(buildDeps(t, all, "one")), oneLiteral)
	require.Greater(t, len(buildDeps(t, all, "two")), twoLiteral)

	scoped, err := NewPackages(ctx, os.DirFS(testdir), testdir, nil, WithCompileOnly("one"))
	require.NoError(t, err)

	t.Run("named package is compiled", func(t *testing.T) {
		require.Equal(t, buildDeps(t, all, "one"), buildDeps(t, scoped, "one"))
	})

	t.Run("unnamed package is not compiled", func(t *testing.T) {
		require.Len(t, buildDeps(t, scoped, "two"), twoLiteral)
	})

	t.Run("local index is unaffected", func(t *testing.T) {
		require.ElementsMatch(t, all.PackageNames(), scoped.PackageNames())

		// Subpackages and provides are registered before Compile runs, so
		// skipping compilation must not remove anything from the index.
		for _, name := range []string{
			"two", "two-provides-implicit", "two-provides-explicit",
			"one-sub1", "one-sub2", "one-subp-provides-implicit",
		} {
			require.NotEmpty(t, scoped.Config(name, false), "%q missing from index", name)
		}
	})

	t.Run("empty set compiles everything", func(t *testing.T) {
		none, err := NewPackages(ctx, os.DirFS(testdir), testdir, nil, WithCompileOnly())
		require.NoError(t, err)
		require.Equal(t, buildDeps(t, all, "two"), buildDeps(t, none, "two"))
	})
}
