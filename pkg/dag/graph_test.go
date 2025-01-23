package dag

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

const (
	packageRepo = "testdata/packages"
	key         = "testdata/packages/wolfi-signing.rsa.pub"
)

func TestNewGraph(t *testing.T) {
	t.Run("basic", func(t *testing.T) {
		ctx := context.Background()
		var (
			testDir = "testdata/basic"
		)
		t.Run("allowed dangling", func(t *testing.T) {
			pkgs, err := NewPackages(ctx, os.DirFS(testDir), testDir, "")
			require.NoError(t, err)
			graph, err := NewGraph(ctx, pkgs, WithAllowUnresolved())
			require.NoError(t, err)
			amap, err := graph.Graph.AdjacencyMap()
			require.NoError(t, err)
			allBusybox := pkgs.Config("busybox", false)
			require.Len(t, allBusybox, 1)
			busybox := allBusybox[0]
			require.Contains(t, amap, PackageHash(busybox))
			busyboxDeps := amap[PackageHash(busybox)]
			expectedDeps := []string{
				"ca-certificates-bundle:@unknown",
				"build-base:@unknown",
				"binutils:@unknown",
				"wget:@unknown",
				"scanelf:@unknown",
				"patch:@unknown",
			}
			assert.Len(t, busyboxDeps, len(expectedDeps)) // 3 direct and 4 from the pipeline
			// the direct dependencies from environment.contents.packages should be dangling, i.e. unresolved
			for _, dep := range expectedDeps {
				assert.Contains(t, busyboxDeps, dep)
				assert.Equal(t, busyboxDeps[dep].Source, PackageHash(busybox))
				assert.Equal(t, busyboxDeps[dep].Target, dep)
				vertex, err := graph.Graph.Vertex(dep)
				require.NoError(t, err)
				assert.False(t, vertex.Resolved())
			}
		})
		t.Run("has expected tree", func(t *testing.T) {
			pkgs, err := NewPackages(ctx, os.DirFS(testDir), testDir, "")
			require.NoError(t, err)
			graph, err := NewGraph(ctx, pkgs, WithRepos(packageRepo), WithKeys(key))
			require.NoError(t, err)
			amap, err := graph.Graph.AdjacencyMap()
			require.NoError(t, err)
			allBusybox := pkgs.Config("busybox", false)
			require.Len(t, allBusybox, 1)
			busybox := allBusybox[0]
			require.Contains(t, amap, PackageHash(busybox))
			busyboxDeps := amap[PackageHash(busybox)]
			// these deps are taken from the environment.contents.packages of testdata/busybox.yaml
			// these do not include versions or sources, which are calculated by the graph.
			// so we need to get the correct deps.
			// We reference the APKINDEX.tar.gz in testdata/packages, which contains the following packages:
			expectedDeps := []string{
				"ca-certificates-bundle:20220614-r1@testdata/packages/x86_64",
				"build-base:1-r2@testdata/packages/x86_64",
				"binutils:2.39-r1@testdata/packages/x86_64",
				"wget:1.21.3-r1@testdata/packages/x86_64",
				"scanelf:1.3.4-r1@testdata/packages/x86_64",
				"patch:2.7.6-r1@testdata/packages/x86_64",
			}
			assert.Len(t, busyboxDeps, len(expectedDeps)) // 3 direct and 4 from the pipeline
			// the direct dependencies from environment.contents.packages should be dangling, i.e. unresolved
			for _, dep := range expectedDeps {
				assert.Contains(t, busyboxDeps, dep)
				assert.Equal(t, busyboxDeps[dep].Source, PackageHash(busybox))
				assert.Equal(t, busyboxDeps[dep].Target, dep)
				vertex, err := graph.Graph.Vertex(dep)
				require.NoError(t, err)
				assert.True(t, vertex.Resolved())
			}
		})
	})
	t.Run("multiple", func(t *testing.T) {
		ctx := context.Background()
		var testDir = "testdata/multiple"
		t.Run("allowed dangling", func(t *testing.T) {
			pkgs, err := NewPackages(ctx, os.DirFS(testDir), testDir, "")
			require.NoError(t, err)
			_, err = NewGraph(ctx, pkgs, WithAllowUnresolved())
			require.NoError(t, err)
		})
		t.Run("external dependencies only", func(t *testing.T) {
			pkgs, err := NewPackages(ctx, os.DirFS(testDir), testDir, "")
			require.NoError(t, err)
			graph, err := NewGraph(ctx, pkgs, WithRepos(packageRepo), WithKeys(key))
			require.NoError(t, err)
			amap, err := graph.Graph.AdjacencyMap()
			require.NoError(t, err)
			configs := pkgs.Config("one", true)
			require.Len(t, configs, 1)

			for _, conf := range configs {
				require.Contains(t, amap, PackageHash(conf))
				deps := amap[PackageHash(conf)]
				expectedDeps := []string{
					"wolfi-baselayout:1-r2@testdata/packages/x86_64",
					"ca-certificates-bundle:20220614-r1@testdata/packages/x86_64",
					"build-base:1-r2@testdata/packages/x86_64",
					"busybox:1.35.0-r2@testdata/packages/x86_64",
					"binutils:2.39-r1@testdata/packages/x86_64",
					"wget:1.21.3-r1@testdata/packages/x86_64",
					"scanelf:1.3.4-r1@testdata/packages/x86_64",
					"make:4.3-r1@testdata/packages/x86_64",
				}
				assert.Len(t, deps, len(expectedDeps))
				// the direct dependencies from environment.contents.packages should be dangling, i.e. unresolved
				for _, dep := range expectedDeps {
					assert.Contains(t, deps, dep)
					assert.Equal(t, deps[dep].Source, PackageHash(conf))
					assert.Equal(t, deps[dep].Target, dep)
					vertex, err := graph.Graph.Vertex(dep)
					require.NoError(t, err)
					assert.True(t, vertex.Resolved())
				}
			}
		})
		t.Run("internal and external dependencies", func(t *testing.T) {
			pkgs, err := NewPackages(ctx, os.DirFS(testDir), testDir, "")
			require.NoError(t, err)
			graph, err := NewGraph(ctx, pkgs, WithRepos(packageRepo), WithKeys(key))
			require.NoError(t, err)
			amap, err := graph.Graph.AdjacencyMap()
			require.NoError(t, err)
			allConfigs := pkgs.Config("three-other", true)
			require.Len(t, allConfigs, 1)
			conf := allConfigs[0]
			require.Contains(t, amap, PackageHash(conf))
			deps := amap[PackageHash(conf)]
			// external dependencies, therefore dangling
			externalDeps := []string{
				"wolfi-baselayout:1-r2@testdata/packages/x86_64",
				"ca-certificates-bundle:20220614-r1@testdata/packages/x86_64",
				"busybox:1.35.0-r2@testdata/packages/x86_64",
			}
			// internal dependencies, therefore resolved
			// we have two "one", so it takes the highest value
			internalDeps := []string{
				"one:1.2.3-r1@local",
				"two:4.5.6-r1@local",
			}
			assert.Len(t, deps, len(externalDeps)+len(internalDeps))
			// the external dependencies should be dangling, i.e. unresolved
			for _, dep := range externalDeps {
				assert.Contains(t, deps, dep)
				assert.Equal(t, deps[dep].Source, PackageHash(conf), "for %s", dep)
				assert.Equal(t, deps[dep].Target, dep)
				vertex, err := graph.Graph.Vertex(dep)
				require.NoError(t, err)
				assert.True(t, vertex.Resolved())
			}
			// the internal dependencies should be resolved
			for _, dep := range internalDeps {
				assert.Contains(t, deps, dep)
				assert.Equal(t, deps[dep].Source, PackageHash(conf), "for %s", dep)
				assert.Equal(t, deps[dep].Target, dep)
				vertex, err := graph.Graph.Vertex(dep)
				require.NoError(t, err)
				assert.Equal(t, PackageHash(vertex), dep)
				assert.True(t, vertex.Resolved())
			}
		})

		t.Run("internal dependencies numbered", func(t *testing.T) {
			pkgs, err := NewPackages(ctx, os.DirFS(testDir), testDir, "")
			require.NoError(t, err)
			graph, err := NewGraph(ctx, pkgs, WithRepos(packageRepo), WithKeys(key))
			require.NoError(t, err)
			amap, err := graph.Graph.AdjacencyMap()
			require.NoError(t, err)
			allConfigs := pkgs.Config("two", true)
			require.Len(t, allConfigs, 1)
			conf := allConfigs[0]
			require.Contains(t, amap, PackageHash(conf))
			deps := amap[PackageHash(conf)]
			// external dependencies, therefore dangling
			externalDeps := []string{
				"wolfi-baselayout:1-r2@testdata/packages/x86_64",
				"ca-certificates-bundle:20220614-r1@testdata/packages/x86_64",
				"build-base:1-r2@testdata/packages/x86_64",
				"busybox:1.35.0-r2@testdata/packages/x86_64",
				"binutils:2.39-r1@testdata/packages/x86_64",
				"wget:1.21.3-r1@testdata/packages/x86_64",
				"scanelf:1.3.4-r1@testdata/packages/x86_64",
				"make:4.3-r1@testdata/packages/x86_64",
			}
			// internal dependencies, therefore resolved
			// we have two "one", so we explicitly pick the lower one
			internalDeps := []string{
				"one:1.2.3-r1@local",
			}
			assert.Len(t, deps, len(externalDeps)+len(internalDeps))
			// the external dependencies should be dangling, i.e. unresolved
			for _, dep := range externalDeps {
				assert.Contains(t, deps, dep)
				assert.Equal(t, deps[dep].Source, PackageHash(conf))
				assert.Equal(t, deps[dep].Target, dep)
				vertex, err := graph.Graph.Vertex(dep)
				require.NoError(t, err)
				assert.True(t, vertex.Resolved())
			}
			// the internal dependencies should be resolved
			for _, dep := range internalDeps {
				assert.Contains(t, deps, dep)
				assert.Equal(t, deps[dep].Source, PackageHash(conf))
				assert.Equal(t, deps[dep].Target, dep)
				vertex, err := graph.Graph.Vertex(dep)
				require.NoError(t, err)
				assert.Equal(t, PackageHash(vertex), dep)
				assert.True(t, vertex.Resolved())
			}
		})
	})
	t.Run("resolve cycle", func(t *testing.T) {
		ctx := context.Background()
		var (
			testDir          = "testdata/cycle"
			cyclePackageRepo = filepath.Join(testDir, "packages")
			cycleKey         = filepath.Join(cyclePackageRepo, "key.rsa.pub")
			expectedDeps     = map[string][]string{
				"a": {"b:1.2.3-r1@local", "c:1.5.5-r1@local", "d:1.0.0-r0@testdata/cycle/packages/x86_64"},
				"b": {"c:1.5.5-r1@local", "d:1.0.0-r0@testdata/cycle/packages/x86_64"},
				"c": {"d:1.0.0-r0@testdata/cycle/packages/x86_64"},
				"d": {"a:1.3.5-r1@local"},
			}
		)
		pkgs, err := NewPackages(ctx, os.DirFS(testDir), testDir, "")
		require.NoError(t, err)
		graph, err := NewGraph(ctx, pkgs, WithRepos(cyclePackageRepo), WithKeys(cycleKey))
		require.NoError(t, err)
		amap, err := graph.Graph.AdjacencyMap()
		require.NoError(t, err)
		for k, v := range expectedDeps {
			allConfigs := pkgs.Config(k, true)
			require.Len(t, allConfigs, 1, "no configs for %s", k)
			confKey := PackageHash(allConfigs[0])
			require.Contains(t, amap, confKey, "missing key %s", confKey)
			var deps []string
			for d := range amap[confKey] {
				deps = append(deps, d)
			}
			assert.ElementsMatch(t, v, deps, "unexpected dependencies for %s", k)
		}
	})
}

func TestTargets(t *testing.T) {
	ctx := context.Background()
	testDir := "testdata/subpackages"

	pkgs, err := NewPackages(ctx, os.DirFS(testDir), testDir, "")
	require.NoError(t, err)
	graph, err := NewGraph(ctx, pkgs, WithAllowUnresolved())
	require.NoError(t, err)
	graph, err = graph.Filter(FilterLocal())
	require.NoError(t, err)
	graph, err = graph.Targets()
	require.NoError(t, err)
	amap, err := graph.Graph.AdjacencyMap()
	require.NoError(t, err)
	expectedDeps := map[string][]string{
		"one:1.2.3-r1@local":   {},
		"two:4.5.6-r1@local":   {"one:1.2.3-r1@local"},
		"three:4.5.6-r1@local": {"two:4.5.6-r1@local"},
	}

	// the direct dependencies from environment.contents.packages should be dangling, i.e. unresolved
	for k, want := range expectedDeps {
		got, ok := amap[k]
		if !ok {
			for k := range amap {
				t.Errorf("found %q", k)
			}
			t.Fatalf("did not find %q", k)
		}

		keys := maps.Keys(got)
		assert.ElementsMatch(t, want, keys, "unexpected dependencies for %s", k)
	}
}
