## Commands

See the [wolfictl check so_name command reference](https://github.com/wolfi-dev/wolfictl/blob/main/docs/cmd/wolfictl_check_so-name.md)

## Usage

This command is expected to be run as part of a CI check.  When a new local apk is built this check will compare any *.so name
file versions against the current version in an apk repository, i.e. https://packages.wolfi.dev/os.

Example scenario:

Current version in wolfi `hello-world-0.0.1-r0.apk` containing a file `foo.so.1`

A Pull Request submitted to wolfi which updates a `hello-world.yaml` melange config package version to `0.0.2`

CI builds a new `hello-world-0.0.2-r0.apk`

`wolfictl check so_name` will run, using a file `packages.log` generated from the wolfi `Makefile` to determine which packages were built as part of that Makefile.  The format of this file will look something like:

```
aarch64|bind|1.2.3-r0
aarch64|gnupg|2.2.41-r0
aarch64|gnutls-c++|3.7.8-r0
```

The check will inspect the new main apk package and related subpackages, fetching the latest current versions from the apk repository and compare the `*.so` files.

If `*.so` files are found then we check that the versions remain the same to ensure ABI compatability.

e.g. if version `0.0.1` contains a file `foo.so.1` and a proposed `0.0.2` contains `foo.so.2` then this command will fail.
