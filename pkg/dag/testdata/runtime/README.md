# Runtime

Test fixtures to support resolving runtime dependencies.

Details are in [graph_test.go](../../graph_test.go), specifically the case named "runtime".

In general, the part of the package `package.dependencies.runtime` is
resolved _only_ using the local repository where the yaml definition
is located.

We want to test several use cases:

* Where it can find it locally, it should succeed.
* Where it cannot find it locally, even if defined in the buildtime dependencies, it should error out.
* Where it cannot find it locally, and it is defined in the buildtime dependencies and we told it to consider buildtime, it should succeed.

The structure is as follows. We have two repositories:

* "local", which represents yaml files in this directory
* "other", which is files in `packages/`

No packages are duplicated between both.

Package naming is intentional, to ensure sort order.

Local packages are:

* a:1.3.5 ; runtime depends on b, d; buildtime includes reference to "other"
* b:1.2.3 ; runtime depends on c
* c:1.5.5 ; no dependencies

Upstream packages are:

* d:1.0.0

The flow we create is as follows.

1. Resolve b with or without buildtime: this should show it depending on:
   * c:1.5.5@local
2. Resolve c with or without buildtime: this should show it depending on nothing
3. Resolve a without buildtime: this should show it depending on:
   * b:1.2.3@local
   * c:1.5.5@local (inherited from b)
   * d: fail!
3. Resolve a with buildtime: this should show it depending on:
   * b:1.2.3@local
   * c:1.5.5@local (inherited from b)
   * d:1.0.0@other

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
$ mkdir -p testdata/runtime/packages
$ mkdir -p testdata/runtime/packages/x86_64
$ melange keygen testdata/runtime/packages/key.rsa
$ tar -C testdata/runtime -czf testdata/runtime/packages/x86_64/APKINDEX.tar.gz APKINDEX
$ melange sign-index --signing-key testdata/runtime/packages/key.rsa testdata/runtime/packages/x86_64/APKINDEX.tar.gz
```

## About APKINDEX

Be _very careful_ if you edit [APKINDEX](./APKINDEX). Some editors like to "clean it up" and remove
trailing newlines. That will break how apk reads the file and miss some packages.