# Graph

Several commands rely open wolfictl generating a graph of build order
for all packages provided in a directory.

This file describes the logic used to determine the build order.

The graph is a directed acyclic graph (DAG) of packages.

## Nodes

Each node on the graph is a build dependency. It can be a package, a subpackage,
or a dependency provided by a package.

The unique ID for each node is a combination of name (package, subpackage or provides), version, and source.

For example, if a configuration yaml has two subpackages and two dependencies,
there will be five nodes on the graph, one each for the package, each of the
subpackages, and each of the dependencies provided by the package. The source for
those five nodes will be "local".

If a package is retrieved from another repository, for example upstream bootstrap
stage 3, then each node will be a package from the stage3 repository. The source
for those packages will be the URL for stage3, i.e. 
https://packages.wolfi.dev/bootstrap/stage3.

The above means that the same package with the different versions are two distinct
nodes, as are the same package with the same version but from different sources.

The components of each node are as follows:

* name: the name of the package, subpackage or provides.
* version: for a package, the version provided; for a subpackage, the version of the package; for a provides, the explicit version, unless not provided, in which case the version of the package.
* source: if the node is from a provided URL repository, then that URL; if the node is from the local list of configuration files, then "local".

For example:

```yaml
package:
  name: two
  version: "4.5.6"
  dependencies:
    provides:
      - two-provides-explicit=10.11.12
      - two-provides-implicit
subpackages:
  - name: one-sub1
  - name: one-sub2
    dependencies:
      provides:
        - one-subp-provides-implicit
        - one-subp-provides-explicit=10.10.11      
```

The above creates the following nodes:

* `two-4.5.6@local` - name is `two`, version is `4.5.6`, source is `local`
* `two-provides-explicit-10.11.12@local` - name is `two-provides-explicit`, version is explicitly `10.11.12`, source is `local` 
* `two-provides-implicit-4.5.6@local` - name is `two-provides-implicit`, version is taken from the package as `4.5.6`, source is `local`
* `one-sub1-4.5.6@local` - name is `one-sub1`, version is taken from the package as `4.5.6`, source is `local`
* `one-sub2-4.5.6@local` - name is `one-sub2`, version is taken from the package as `4.5.6`, source is `local`

## Edges

Each edge is a directed dependency between two nodes. The edge is directed from
the node that depends on the other node.

For example, if package A requires package B to build, then there will be an edge
from node A to node B.

* Each subpackage and each provides has an edge showing a dependency on the package.
* Each package that depends on another package has an edge showing a dependency on the other package.

For example:
    
```yaml
package:
  name: one
  version: "1.2.3"
  dependencies:
    runtime:
      - bash
      - gcc
```

The above creates the following edges; the dependencies are left simple in the below example for clarity, not including the version or source:

* `one-1.2.3@local` -> `bash`
* `one-1.2.3@local` -> `gcc`

## Resolution of Dependencies

The DAG uses the following logic to resolve dependencies:

1. Find all subpackages and provides, create dependencies on their origin packages.
1. For each package, find all dependencies:
   * Explicit, listed in the configuration file as `environment.content.packages`
   * Implicit, required by pipeline steps as part of the pipeline `uses`
1. For each dependency, create a dependency from the package to the node that matches the dependency. Use apk tools resolution logic to find the correct version of the node that provides the package. See below.

Note that the dependency is as fine-grained and explicit as possible. If two
packages exist, A and B, and A provides D, upon which B depends, then the
dependency will be from B to D, which in turn depends upon A; the dependency
will *not* be from B directly to A.

   B -> D -> A

Various output formats may resolve that D is just a "provides", and that the
actual dependency is on the package A; the graph itself tries to maintain the
maximum amount of information.

Similarly for subpackages. If A has a subpackage S, and B depends on S, then the
dependency will be from B to S, which in turn depends upon A; the dependency
will *not* be from B directly to A.

   B -> S -> A

## Resolution of Dependency Version

The version of a dependency is resolved using the standard apk tools
logic. Specifically, take the highest version of the package name, subpackage
or provides that meets the version constraints, if any, across all
repositories.

For example, assume local has a yaml file that will build bash 5.0.0, while
stage3 has bash 4.0.0

* If a package depends on `bash`, then the dependency will be on `bash-5.0.0@local`.
* If the package depends on `bash=4.0.0`, then the dependency will be on `bash-4.0.0@stage3`.
* If the package depends on `bash>=4.0.0`, then the dependency will be on `bash-5.0.0@local`.

As a general rule, if a package with the same name appears in both local and stage3,
the local package will have a higher version than the stage3 package, leading it to
be selected. This is by design and preferred.

## Resolving Cyclical Dependencies

It is possible to have cyclical dependencies. For example, package A depends
on package B, and package B depends on package A. The versions in the repositories
are as follows:

|Package|stage3|local|
|---|---|---|
|A|1.0.0|2.0.0|
|B|1.0.0|2.0.0|

Note that both packages have lower versions in stage3 than in local, which is to
be expected.

This would create a cycle, as both would prefer the higher version 2.0.0, which
cannot be built without the other.

The resolution for this case is:

* A depends upon B-1.0.0@stage3
* B depends upon A-2.0.0@local

The graph breaks the cycle by making the second package in the cycle - i.e. the first
to create a cycle - use the lower version from the other repository.
A was resolved first, so it gets to use B from local. Only then is B resolved, and
it must use A from stage3 or create a cycle.

   A@local -> B@local -> A@stage3

This is rather arbitrary, as B is being resolved later only due to its alphabetical
ordering. We are aware of this and may change the resolution logic in the future.

However, this does not always work. Consider the following case. A depends on B,
B depends on A. While B is available both local and in stage3, A is available only locally.

|Package|stage3|local|
|---|---|---|
|A||2.0.0|
|B|1.0.0|2.0.0|

Whether or not this successfully resolves depends which package we process first.

* B first: B -> A@local (works); then A -> B@local (fails, due to cycle), so try to fall back to B@stage3 (works)
* A first: A -> B@local (works); then B -> A@local (fails, due to cycle), so try to fall back to A@stage3 (fails, not available)

We cannot know before processing the graph if the order matters. Thus, the graph does the following:

1. A first, as A is earlier alphabetically.
1. A -> B@local (works)
1. B -> A@local (fails, due to cycle)
1. B -> A@stage3
   * if it succeeds, done
   * if it fails, continue
1. report the edges that create the cycle and try to resolve by reversing them

It does not rebuild A's edges entirely. It does, however, remove the particular edge A -> B@local, try to resolve B -> A,
and then try to redo A -> B, which will resolve to A -> B@stage3.

Note that the above only can handle cycles that involve pairs, i.e. A -> B and B -> A. It cannot handle A -> B -> C and C -> A.