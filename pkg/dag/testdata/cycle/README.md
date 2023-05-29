# Cycle

Test fixtures to support resolving cycles.

Details are in [graph_test.go](../../graph_test.go), specifically the case named "resolve cycle".

What we want is to set up a case so that we have a chain of dependencies set up, and then try to reverse
them. This, in turn, should lead to unwinding all of the end dependencies, doing the reverse dependency,
and then redoing the unwound dependencies, finding a lower one from elsewhere.

The structure is something like this. We have two repositories:

* "local", which represents yaml files in this directory
* "upstream", which is files in `packages/`

Some of the packages in "local" also are in "upstream", but at lower versions; others
are not.

The goal of the test is to ensure that cycles can be resolved properly. The initial dependencies
are resolved locally. The final package resolved depends on something that is
available only locally, yet creates several paths to cycles.
This should cause some of the existing dependencies to unwind, resolve the one that would cause a cycle, and then return the ones that we unwound, which now should resolve to upstream.

Package naming is intentional, to ensure sort order.

Local packages are:

* a:1.3.5 ; depends on b, c, d
* b:1.2.3 ; depends on c, d
* c:1.5.5 ; depends on d
* d:2.0.0 ; depends on a

Upstream packages are:

* b:1.0.0
* c:1.0.0
* d:1.0.0

The flow we create is as follows.

1. Resolve a: this should show it depending on:
   * b:1.2.3@local
   * c:1.5.5@local
   * d:2.0.0@local
2. Resolve b: this should show it depending on:
   * c:1.5.5@local
   * d:2.0.0@local
3. Resolve c: this should show it depending on:
   * d:2.0.0@local
4. Resolve d: this depends on a, so it should create the cycle.

Resolving the cycle should unwind:

* a -> d:2.0.0@local
* b -> d:2.0.0@local
* c -> d:2.0.0@local

Then d -> a should resolve:

* d -> a:1.3.5@local

Finally, it should return the unwound dependencies, with their new dependencies:

* a -> d:1.0.0@upstream
* b -> d:1.0.0@upstream
* c -> d:1.0.0@upstream

## Generating the package directory

The contents of the "upstream" need only be as follows:

* `cycle/packages/key.rsa.pub` - the public key
* `cycle/packages/x86_64/APKINDEX.tar.gz` - the package index

We do not need the actual apk files, as they are not used in this test.

To do this:

1. Generate the key
1. Create the `APKINDEX.tar.gz` from [APKINDEX](./APKINDEX)
1. Sign the index

From within the `pkg/dag/` directory:

```shell
$ mkdir -p testdata/cycle/packages
$ mkdir -p testdata/cycle/packages/x86_64
$ melange keygen testdata/cycle/packages/key.rsa
$ tar -C testdata/cycle -czf testdata/cycle/packages/x86_64/APKINDEX.tar.gz APKINDEX
$ melange sign-index --signing-key testdata/cycle/packages/key.rsa testdata/cycle/packages/x86_64/APKINDEX.tar.gz
```

## About APKINDEX

Be _very careful_ if you edit [APKINDEX](./APKINDEX). Some editors like to "clean it up" and remove
trailing newlines. That will break how apk reads the file and miss some packages.