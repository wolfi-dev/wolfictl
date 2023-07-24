package dag

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/dominikbraun/graph"
	log "github.com/sirupsen/logrus"
	"gitlab.alpinelinux.org/alpine/go/repository"
	"go.lsp.dev/uri"

	apk "github.com/chainguard-dev/go-apk/pkg/apk"
)

const (
	attributePkgList = "package-list"
	attributeDepName = "dependency-name"
)

// Graph represents an interdependent set of packages defined in one or more Melange configurations,
// as defined in Packages, as well as upstream repositories and their package indexes,
// as declared in those configurations files. The graph is directed and acyclic.
type Graph struct {
	Graph     graph.Graph[string, Package]
	packages  *Packages
	opts      *graphOptions
	resolvers map[string]*apk.PkgResolver // maintains a listing of all resolvers by key
	byName    map[string][]string         // maintains a listing of all known hashes for a given name
}

// packageHash given anything that implements Package, return the hash to be used
// for the node in the graph.
func packageHash(p Package) string {
	return p.Name() + ":" + p.Version() + "@" + p.Source()
}

func newGraph() graph.Graph[string, Package] {
	return graph.New(packageHash, graph.Directed(), graph.Acyclic(), graph.PreventCycles())
}

// cycle represents pairs of edges that create a cycle in the graph
type cycle struct {
	src, target string
	attrs       map[string]string
}

// NewGraph returns a new Graph using the packages, including names and versions, in the Packages struct.
// It parses the packages to create the dependency graph.
// If the list of packages creates a cycle, an error is returned.
// If a package cannot be resolved, an error is returned, unless WithAllowUnresolved is set.
func NewGraph(ctx context.Context, pkgs *Packages, options ...GraphOptions) (*Graph, error) {
	var opts = &graphOptions{}
	for _, option := range options {
		if err := option(opts); err != nil {
			return nil, err
		}
	}
	g := &Graph{
		Graph:     newGraph(),
		packages:  pkgs,
		opts:      opts,
		resolvers: make(map[string]*apk.PkgResolver),
		byName:    map[string][]string{},
	}

	// indexes is a cache of all repositories. Only some might be used for each package.
	var (
		indexes = make(map[string]apk.NamedIndex)
		keys    = make(map[string][]byte)
		errs    []error
	)

	// TODO: should we repeat across multiple arches? Use c.Package.TargetArchitecture []string
	var arch = "x86_64"
	localRepo := pkgs.Repository(arch)
	localRepoSource := localRepo.Source()
	localOnlyResolver := apk.NewPkgResolver(ctx, []apk.NamedIndex{localRepo})
	g.resolvers[localRepoSource] = localOnlyResolver

	// the order of adding packages is quite important:
	// 1. Go through each origin package and add it as a vertex
	// 2. Go through each of its subpackages and add them as vertices, with the sub dependent on the origin
	// 3. Add runtime dependencies for each package, as they are much more constrained than the build-time, and only can go to the local repo.
	// 4. Add environment build-time dependencies
	for _, c := range pkgs.Packages() {
		if err := g.addVertex(c); err != nil && !errors.Is(err, graph.ErrVertexAlreadyExists) {
			errs = append(errs, err)
			continue
		}
		// add the origin package as its own resolver, so that the subpackage can resolve to it
		g.resolvers[c.String()] = singlePackageResolver(ctx, c, arch)
		for i := range c.Subpackages {
			subpkg := pkgs.Config(c.Subpackages[i].Name, false)
			for _, subpkgVersion := range subpkg {
				if err := g.addVertex(subpkgVersion); err != nil && !errors.Is(err, graph.ErrVertexAlreadyExists) {
					errs = append(errs, fmt.Errorf("unable to add vertex for %q subpackage %s-%s: %w", c.String(), subpkgVersion.Name(), subpkgVersion.Version(), err))
					continue
				}
				parentHash := packageHash(c)
				attrs := map[string]string{
					attributePkgList: parentHash,
				}
				if err := g.Graph.AddEdge(packageHash(subpkgVersion), parentHash, graph.EdgeAttributes(attrs)); err != nil && !errors.Is(err, graph.ErrEdgeAlreadyExists) {
					// a subpackage always must depend on its origin package. It is not acceptable to have any errors, other than that we already know about that dependency.
					errs = append(errs, fmt.Errorf("unable to add edge for subpackage %q from %s-%s: %w", c.String(), subpkgVersion.Name(), subpkgVersion.Version(), err))
					continue
				}
			}
		}
	}

	for _, c := range pkgs.Packages() {
		// add packages from the runtime dependencies first, as they are constrained to the local repository
		// For runtime packages, it is allowed to resolve itself.
		addErrs := g.resolvePackages(c, "runtime", localRepoSource, localRepoSource, c.Package.Dependencies.Runtime, true)
		if len(addErrs) > 0 {
			errs = append(errs, addErrs...)
		}
	}

	for _, c := range pkgs.Packages() {
		// get all of the repositories that are referenced by the package
		var (
			origRepos   = c.Environment.Contents.Repositories
			origKeys    = c.Environment.Contents.Keyring
			repos       []string
			lookupRepos = []apk.NamedIndex{}
			// validKeys contains list of keys valid for this package; as opposed to
			// keys, which is the master list of all keys we have encountered
			validKeys = map[string][]byte{}
		)
		for _, repo := range append(origRepos, opts.repos...) {
			key := apk.IndexURL(repo, arch)
			if index, ok := indexes[key]; !ok {
				repos = append(repos, repo)
			} else {
				lookupRepos = append(lookupRepos, index)
			}
		}
		// ensure any keys listed in this package are in the master map of keys
		for _, key := range append(origKeys, opts.keys...) {
			if _, ok := keys[key]; ok {
				validKeys[key] = keys[key]
				continue
			}
			b, err := getKeyMaterial(key)
			if err != nil {
				return nil, fmt.Errorf("failed to get key material for %s: %w", key, err)
			}
			// we can have no error, but still no bytes, as we ignore missing files
			if b != nil {
				keys[key] = b
				validKeys[key] = b
			}
		}
		if len(repos) > 0 {
			loadedRepos, err := apk.GetRepositoryIndexes(ctx, repos, keys, arch)
			if err != nil {
				return nil, fmt.Errorf("unable to load repositories for %s: %w", c.String(), err)
			}
			for _, repo := range loadedRepos {
				indexes[repo.Source()] = repo
				lookupRepos = append(lookupRepos, repo)
			}
		}

		// add our own packages list to the lookupRepos
		lookupRepos = append(lookupRepos, localRepo)

		// creating a resolver can be expensive, so we cache any that already exist that have exactly
		// the same repositories.
		// This does leave an extra "," at the end, but it doesn't really matter, it is good enough.
		// Anything else would require converting it into []string and then joining it,
		// which is more expensive unnecessarily.
		var (
			keys    []string
			addErrs []error
		)
		for _, repo := range lookupRepos {
			keys = append(keys, repo.Source())
		}
		resolverKey := strings.Join(keys, ",")

		// add packages from build-time, as they could be local only, or might have upstream
		if _, ok := g.resolvers[resolverKey]; !ok {
			g.resolvers[resolverKey] = apk.NewPkgResolver(ctx, lookupRepos)
		}
		// wolfi-dev has a policy for environment packages not to use a package to fulfull a dependency, if that package is myself.
		// if I depend on something, and the dependency is the same name as me, it must have a lower version than myself
		addErrs = g.resolvePackages(c, "environment", localRepoSource, resolverKey, c.Environment.Contents.Packages, false)
		if len(addErrs) > 0 {
			errs = append(errs, addErrs...)
		}

		// we also need to add packages that are in Packages.Dependencies.Runtime, but these should come *only*
		// from local
	}
	if errs != nil {
		return nil, fmt.Errorf("unable to build graph:\n%w", errors.Join(errs...))
	}

	return g, nil
}

// resolvePackages given a package `parent`, a list of packages `pkgs` and a `resolver`,
// use the resolver to find all of the packages that fulfill the requirements and add them
// to the graph as the parent's dependencies.
// Optionally, can allow self to resolve dependencies or not. This is policy driven/
// In general, wolfi/os does *not* allow self to resolve for build environment,
// and *does* allow self to resolve for runtime environment.
func (g *Graph) resolvePackages(parent *Configuration, source, localRepoSource, resolverKey string, pkgs []string, allowSelf bool) (errs []error) {
	for _, buildDep := range pkgs {
		if buildDep == "" {
			errs = append(errs, fmt.Errorf("empty package name in %s packages for %q", source, parent.Package.Name))
			continue
		}
		// handle the negative for a package
		// if it was a conflict prevention, we do not care about it for graph, only for install time
		if strings.HasPrefix(buildDep, "!") {
			continue
		}

		cycle, err := g.addAppropriatePackageFromResolver(resolverKey, parent, buildDep, localRepoSource, allowSelf)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		// resolve any cycle
		if cycle != nil {
			if sp, err := g.resolveCycle(cycle, buildDep); err != nil {
				log.Errorf("unresolvable cycle: %s -> %s, caused by: %s", cycle.src, cycle.target, strings.Join(sp, " -> "))
				errs = append(errs, err)
				continue
			}
		}
	}
	return
}

// addAppropriatePackageFromResolver adds the appropriate package to the graph, and returns any cycle that was created.
// The c *Configuration is the source package, while the dep represents the dependency.
// Whether or not this package is allowed to resolve itself is policy driven.
func (g *Graph) addAppropriatePackageFromResolver(resolverKey string, c Package, dep, localRepo string, allowSelf bool) (*cycle, error) {
	var (
		pkg    Package
		pkgKey = packageHash(c)
	)
	resolver, ok := g.resolvers[resolverKey]
	if !ok {
		return nil, fmt.Errorf("unable to find resolver for %s", resolverKey)
	}
	resolved, err := resolver.ResolvePackage(dep)
	switch {
	case (err != nil || len(resolved) == 0) && g.opts.allowUnresolved:
		if err := g.addDanglingPackage(dep, c); err != nil {
			return nil, fmt.Errorf("%s: unable to add dangling package %s: %w", c, dep, err)
		}
	case (err != nil || len(resolved) == 0):
		return nil, fmt.Errorf("%s: unable to resolve dependency %s: %w", c, dep, err)
	default:
		// no error and we had at least one package listed in `resolved`
		// make a list of all the possible packages that could fulfill this dependency
		var (
			matchList = make([]string, 0, len(resolved))
			pkgs      = make([]Package, 0, len(resolved))
		)
		for _, r := range resolved {
			// if we allow self, and our name or origin is the same as dep, and the version is the same, then we are done
			isSelf := r.Version == c.Version() && (dep == c.Name() || r.Origin == c.Name())
			if allowSelf && isSelf {
				return nil, nil
			}
			// we do not allow self, so if match, ignore it and look for next one
			if isSelf {
				continue
			}
			resolvedSource := r.Repository().IndexUri()
			if resolvedSource == localRepo {
				// it's in our own packages list, so find the package that is an actual match
				configs := g.packages.Config(r.Name, false)
				if len(configs) == 0 {
					return nil, fmt.Errorf("unable to find package %s-%s in local repository", r.Name, r.Version)
				}
				for _, config := range configs {
					if fullVersion(&config.Package) == r.Version {
						pkg = config
						break
					}
				}
				if pkg == nil {
					return nil, fmt.Errorf("unable to find package %s-%s in local repository", r.Name, r.Version)
				}
			} else {
				pkg = externalPackage{r.Name, r.Version, r.Repository().Uri}
			}
			if err := g.addVertex(pkg); err != nil && !errors.Is(err, graph.ErrVertexAlreadyExists) {
				return nil, fmt.Errorf("unable to add vertex for %s dependency %s: %w", c, dep, err)
			}
			pkgs = append(pkgs, pkg)
			matchList = append(matchList, packageHash(pkg))
		}
		var (
			allPkgs = strings.Join(matchList, " ")
			attrs   = map[string]string{
				attributePkgList: allPkgs,
				attributeDepName: dep,
			}
		)
		// make sure the vertexes exist
		for _, p := range pkgs {
			if err := g.addVertex(p); err != nil && !errors.Is(err, graph.ErrVertexAlreadyExists) {
				return nil, fmt.Errorf("unable to add vertex for %s dependency %s: %w", c, dep, err)
			}
		}
		// try to add from the list
		cycle, err := g.addAppropriatePackageFromList(pkgKey, matchList, attrs)
		if err != nil {
			return nil, fmt.Errorf("unable to add %s dependency %s: %w", c, dep, err)
		}
		if cycle != nil {
			return cycle, nil
		}
	}
	return nil, nil
}

func (g *Graph) addAppropriatePackageFromList(pkgKey string, matchList []string, attrs map[string]string) (*cycle, error) {
	var cycleTarget string
	for _, target := range matchList {
		err := g.Graph.AddEdge(pkgKey, target, graph.EdgeAttributes(attrs))
		switch {
		case err == nil || errors.Is(err, graph.ErrEdgeAlreadyExists):
			// no error, so we can keep the vertex and we have our match
			return nil, nil
		case errors.Is(err, graph.ErrEdgeCreatesCycle):
			// created a cycle, so track it
			if cycleTarget == "" {
				cycleTarget = target
			}
			continue
		default:
			return nil, fmt.Errorf("%s: add edge dependency %s error: %w", pkgKey, attrs[attributeDepName], err)
		}
	}
	// if we got this far, nothing we added had no error, so we have a cycle
	return &cycle{src: pkgKey, target: cycleTarget, attrs: attrs}, nil
}

// resolveCycle resolves a cycle by trying to reverse the order.
// It discovers what the current dependency is that is causing the potential loop,
// removes the last edge in that cycle, and regenerates that dependency without the previous target.
func (g *Graph) resolveCycle(c *cycle, dep string) ([]string, error) {
	// cycle through, removing all "shortest path" until we can resolve the cycle,
	// then add them back
	var (
		removed []cycle
	)
	origSp, err := graph.ShortestPath(g.Graph, c.target, c.src)
	if err != nil {
		return nil, fmt.Errorf("unable to find shortest path: %w", err)
	}
	var (
		sp    = origSp
		found bool
	)
	for {
		var loop bool
		// start with the last one
		for i := len(sp) - 1; i >= 1; i-- {
			removeSrc, removeTarget := sp[i-1], sp[i]

			edge, err := g.Graph.Edge(removeSrc, removeTarget)
			if err != nil {
				return origSp, fmt.Errorf("unable to find last edge %s -> %s: %w", removeSrc, removeTarget, err)
			}
			if edge.Properties.Attributes == nil {
				return origSp, fmt.Errorf("original edge %s -> %s has no attributes", removeSrc, removeTarget)
			}
			// get the size of the possible candidates
			candidates := strings.Split(edge.Properties.Attributes[attributePkgList], " ")

			// if we have only one candidate, we can't remove it
			if len(candidates) < 2 {
				continue
			}
			// Try to remove the edge we are testing, add back the original, and then
			// add the one we removed. If it works, we are done. If not,
			// move one step higher in the shortestpath chain.
			if err := g.Graph.RemoveEdge(removeSrc, removeTarget); err != nil {
				return origSp, fmt.Errorf("unable to remove original edge %s -> %s: %w", removeSrc, removeTarget, err)
			}
			// see if we would be able to add the edge in now
			newSp, err := graph.ShortestPath(g.Graph, c.target, c.src)
			switch {
			case err != nil:
				// it would work
				if err := g.Graph.AddEdge(c.src, c.target, graph.EdgeAttributes(c.attrs)); err != nil {
					return origSp, fmt.Errorf("unable to add edge back in, even though it should not create a cycle %s -> %s: %w", c.src, c.target, err)
				}
				// it worked, so now see if we can put the original back
				for i := 1; i < len(candidates); i++ {
					candidate := candidates[i]
					err = g.Graph.AddEdge(removeSrc, candidate, graph.EdgeAttributes(edge.Properties.Attributes))
					if err == nil {
						found = true
						break
					}
				}
				if found {
					i = 0
					break
				}
				if err := g.Graph.RemoveEdge(c.src, c.target); err != nil {
					return origSp, fmt.Errorf("unable to remove edge %s -> %s: %w", c.src, c.target, err)
				}
			case reflect.DeepEqual(newSp, sp):
				// the new shortest path is the same as the old one, so removing this one does not help
				if err := g.Graph.AddEdge(removeSrc, removeTarget, graph.EdgeAttributes(edge.Properties.Attributes)); err != nil {
					return origSp, fmt.Errorf("unable to add edge back in, even though it should not create a cycle %s -> %s: %w", removeSrc, removeTarget, err)
				}
			default:
				// not the same, so there must be multiple paths to the target
				// keep this one removed, this shortestpath cycle is done, look for the next one
				removed = append(removed, cycle{src: removeSrc, target: removeTarget, attrs: edge.Properties.Attributes})
				sp = newSp
				i = 0
				loop = true
			}
		}
		// if we made it this far, we ran through the entire current shortestpath,
		// so we can break out of the loop
		if !loop {
			break
		}
	}
	if !found {
		return origSp, fmt.Errorf("there is no single step to remove to clear from %s to %s", c.target, c.src)
	}
	// at this point, we should have removed exactly one edge
	// now we need to re-add the edges that were removed, but with different targets
	for _, rem := range removed {
		origDep := rem.attrs[attributeDepName]
		config, err := g.Graph.Vertex(rem.src)
		if err != nil {
			return origSp, fmt.Errorf("unable to find original vertex %s: %w", rem.src, err)
		}
		cycle, err := g.addAppropriatePackageFromList(packageHash(config), strings.Split(rem.attrs[attributePkgList], " "), rem.attrs)
		if err != nil {
			return origSp, fmt.Errorf("unable to re-add original edge %s -> %s: %w", rem.src, origDep, err)
		}
		if cycle != nil {
			return origSp, fmt.Errorf("unable to re-add original edge with new dep still causes cycle %s -> %s", rem.src, dep)
		}
	}
	return origSp, nil
}

// addVertex adds a vertex to the internal graph, while also tracking its hash by name
func (g *Graph) addVertex(pkg Package) error {
	if err := g.Graph.AddVertex(pkg); err != nil {
		return err
	}
	g.byName[pkg.Name()] = append(g.byName[pkg.Name()], packageHash(pkg))
	return nil
}

func (g *Graph) addDanglingPackage(name string, parent Package) error {
	pkg := danglingPackage{name}
	if err := g.addVertex(pkg); err != nil && !errors.Is(err, graph.ErrVertexAlreadyExists) {
		return err
	}
	if err := g.Graph.AddEdge(packageHash(parent), packageHash(pkg)); err != nil && !errors.Is(err, graph.ErrEdgeAlreadyExists) {
		return err
	}
	return nil
}

// Sorted returns a list of all package names in the Graph, sorted in topological
// order, meaning that packages earlier in the list depend on packages later in
// the list.
func (g Graph) Sorted() ([]Package, error) {
	nodes, err := graph.StableTopologicalSort(g.Graph, func(i string, j string) bool {
		return i > j
	})
	if err != nil {
		return nil, err
	}
	pkgs := make([]Package, len(nodes))
	for i, n := range nodes {
		pkgs[i], err = g.Graph.Vertex(n)
		if err != nil {
			return nil, err
		}
	}
	return pkgs, nil
}

// ReverseSorted returns a list of all package names in the Graph, sorted in reverse
// topological order, meaning that packages later in the list depend on packages earlier
// in the list.
func (g Graph) ReverseSorted() ([]Package, error) {
	pkgs, err := g.Sorted()
	if err != nil {
		return nil, err
	}
	for i, j := 0, len(pkgs)-1; i < j; i, j = i+1, j-1 {
		pkgs[i], pkgs[j] = pkgs[j], pkgs[i]
	}
	return pkgs, nil
}

// SubgraphWithRoots returns a new Graph that's a subgraph of g, where the set of
// the new Graph's roots will be identical to or a subset of the given set of
// roots.
//
// In other words, the new subgraph will contain all dependencies (transitively)
// of all packages whose names were given as the `roots` argument.
func (g Graph) SubgraphWithRoots(ctx context.Context, roots []string) (*Graph, error) {
	// subgraph needs to create a new graph, but it also has a subset of Packages
	subPkgs, err := g.packages.Sub(roots...)
	if err != nil {
		return nil, err
	}
	return NewGraph(ctx, subPkgs)
}

// SubgraphWithLeaves returns a new Graph that's a subgraph of g, where the set of
// the new Graph's leaves will be identical to or a subset of the given set of
// leaves.
//
// In other words, the new subgraph will contain all packages (transitively) that
// are dependent on the packages whose names were given as the `leaves` argument.
func (g Graph) SubgraphWithLeaves(leaves []string) (*Graph, error) {
	subgraph := &Graph{
		Graph:  newGraph(),
		opts:   g.opts,
		byName: map[string][]string{},
	}
	var names []string

	predecessorMap, err := g.Graph.PredecessorMap()
	if err != nil {
		return nil, err
	}

	var walk func(key string) error // Go can be so awkward sometimes!
	walk = func(key string) error {
		c := g.packages.ConfigByKey(key)
		if c == nil {
			return fmt.Errorf("unable to find package %q", key)
		}
		if err := subgraph.addVertex(c); err != nil && !errors.Is(err, graph.ErrVertexAlreadyExists) {
			return err
		}
		names = append(names, key)

		for dependent := range predecessorMap[key] {
			c := g.packages.ConfigByKey(dependent)
			if c == nil {
				return fmt.Errorf("unable to find package %q", dependent)
			}
			if err := subgraph.addVertex(c); err != nil && !errors.Is(err, graph.ErrVertexAlreadyExists) {
				return err
			}
			if err := subgraph.Graph.AddEdge(dependent, key); err != nil && !errors.Is(err, graph.ErrEdgeAlreadyExists) {
				return err
			}

			if err := walk(dependent); err != nil {
				return err
			}
		}
		return nil
	}

	for _, leaf := range leaves {
		if err := walk(leaf); err != nil {
			return nil, err
		}
	}

	subPkgs, err := g.packages.Sub(names...)
	if err != nil {
		return nil, err
	}
	subgraph.packages = subPkgs
	return subgraph, nil
}

// Filter is a function that takes a Package and returns true if the Package
// should be included in the filtered Graph, or false if it should be excluded.
type Filter func(Package) bool

// FilterSources returns a Filter that returns true if the Package's source
// matches one of the provided sources, or false otherwise
func FilterSources(source ...string) Filter {
	return func(p Package) bool {
		src := p.Source()
		for _, s := range source {
			if src == s {
				return true
			}
		}
		return false
	}
}

// FilterNotSources returns a Filter that returns false if the Package's source
// matches one of the provided sources, or true otherwise
func FilterNotSources(source ...string) Filter {
	return func(p Package) bool {
		src := p.Source()
		for _, s := range source {
			if src == s {
				return false
			}
		}
		return true
	}
}

// FilterLocal returns a Filter that returns true if the Package's source
// matches the local source, or false otherwise.
func FilterLocal() Filter {
	return FilterSources(Local)
}

// FilterNotLocal returns a Filter that returns true if the Package's source
// matches the local source, or false otherwise.
func FilterNotLocal() Filter {
	return FilterNotSources(Local)
}

// Filter returns a new Graph that's a subgraph of g, where the set of nodes
// in the new graph are filtered by the provided parameters.
// Must provide a func to which each Vertex of type Package is processed, and should return
// true to keep the Vertex and all references to it, or false to remove the Vertex
// and all references to it.
// Some convenience functions are provided for common filtering needs.
func (g Graph) Filter(filter Filter) (*Graph, error) {
	subgraph := &Graph{
		Graph:    newGraph(),
		packages: g.packages,
		opts:     g.opts,
		byName:   map[string][]string{},
	}
	adjacencyMap, err := g.Graph.AdjacencyMap()
	if err != nil {
		return nil, err
	}

	// do this in 2 passes
	// first pass, add all vertices that pass the filter
	// second pass, add all edges whose source and dest are in the new graph
	for node := range adjacencyMap {
		vertex, err := g.Graph.Vertex(node)
		if err != nil {
			return nil, err
		}
		if !filter(vertex) {
			continue
		}
		if err := subgraph.addVertex(vertex); err != nil && !errors.Is(err, graph.ErrVertexAlreadyExists) {
			return nil, err
		}
	}

	for node, deps := range adjacencyMap {
		if _, err := subgraph.Graph.Vertex(node); err != nil {
			continue
		}
		for dep, edge := range deps {
			if _, err := subgraph.Graph.Vertex(dep); err != nil {
				continue
			}
			// both the node and the dependency are in the new graph, so keep the edge
			if err := subgraph.Graph.AddEdge(edge.Source, edge.Target); err != nil && !errors.Is(err, graph.ErrEdgeAlreadyExists) {
				return nil, err
			}
		}
	}
	return subgraph, nil
}

// DependenciesOf returns a slice of the names of the given package's dependencies, sorted alphabetically.
func (g Graph) DependenciesOf(node string) []string {
	adjacencyMap, err := g.Graph.AdjacencyMap()
	if err != nil {
		return nil
	}

	var dependencies []string

	if deps, ok := adjacencyMap[node]; ok {
		for dep := range deps {
			dependencies = append(dependencies, dep)
		}

		// sort for deterministic output
		sort.Strings(dependencies)
		return dependencies
	}

	return nil
}

// Packages returns a slice of the names of all origin packages, sorted alphabetically.
func (g Graph) Packages() []string {
	return g.packages.PackageNames()
}

// Nodes returns a slice of all of the nodes in the graph, sorted alphabetically.
// Unlike Packages, this includes subpackages, provides, etc.
func (g Graph) Nodes() (nodes []string, err error) {
	m, err := g.Graph.AdjacencyMap()
	if err != nil {
		return nil, err
	}
	for node := range m {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	return
}

// NodesByName returns a slice of all of the nodes in the graph for which
// the Vertex's Name() matches the provided name. The sorting order is not guaranteed.
func (g Graph) NodesByName(name string) (pkgs []Package, err error) {
	for _, node := range g.byName[name] {
		pkg, err := g.Graph.Vertex(node)
		if err != nil {
			return nil, err
		}
		pkgs = append(pkgs, pkg)
	}
	return
}

func getKeyMaterial(key string) ([]byte, error) {
	var (
		b     []byte
		asURI uri.URI
		err   error
	)
	if strings.HasPrefix(key, "https://") {
		asURI, err = uri.Parse(key)
		if err != nil {
			return nil, fmt.Errorf("failed to parse key %s as URI: %w", key, err)
		}
	} else {
		asURI = uri.New(key)
	}
	asURL, err := url.Parse(string(asURI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse key %s as URI: %w", key, err)
	}

	switch asURL.Scheme {
	case "file":
		b, err = os.ReadFile(key)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("failed to read repository %s: %w", key, err)
			}
			return nil, nil
		}
	case "https":
		client := &http.Client{}
		res, err := client.Get(asURL.String())
		if err != nil {
			return nil, fmt.Errorf("unable to get key at %s: %w", key, err)
		}
		defer res.Body.Close()
		buf := bytes.NewBuffer(nil)
		if _, err := io.Copy(buf, res.Body); err != nil {
			return nil, fmt.Errorf("unable to read key at %s: %w", key, err)
		}
		b = buf.Bytes()
	default:
		return nil, fmt.Errorf("key scheme %s not supported", asURL.Scheme)
	}
	return b, nil
}

func singlePackageResolver(ctx context.Context, pkg *Configuration, arch string) *apk.PkgResolver {
	repo := repository.NewRepositoryFromComponents(Local, "latest", "", arch)
	packages := []*repository.Package{
		{
			Arch:         arch,
			Name:         pkg.Package.Name,
			Version:      fullVersion(&pkg.Package),
			Description:  pkg.Package.Description,
			License:      pkg.Package.LicenseExpression(),
			Origin:       pkg.Package.Name,
			URL:          pkg.Package.URL,
			Dependencies: pkg.Environment.Contents.Packages,
			Provides:     pkg.Package.Dependencies.Provides,
			RepoCommit:   pkg.Package.Commit,
		},
	}
	index := &repository.ApkIndex{
		Description: pkg.String(),
		Packages:    packages,
	}
	idx := apk.NewNamedRepositoryWithIndex("", repo.WithIndex(index))
	return apk.NewPkgResolver(ctx, []apk.NamedIndex{idx})
}
