## wolfictl test



### Usage

```
wolfictl test
```

### Synopsis

Test wolfi packages. Accepts either no positional arguments (for testing everything) or a list of packages to test.

### Examples


    # Test everything for every x86_64 and aarch64
    wolfictl test

    # Test a few packages
    wolfictl test \
      --arch aarch64 \
      hello-wolfi wget


    # Test a single local package
    wolfictl test \
      --arch aarch64 \
      -k local-melange.rsa.pub \
      -r ./packages \
      -r https://packages.wolfi.dev/os \
      -k https://packages.wolfi.dev/os/wolfi-signing.rsa.pub \
      hello-wolfi
    

### Options

```
      --arch strings                  arch of package to build (default [x86_64,aarch64])
      --cache-dir string              directory used for cached inputs (default "./melange-cache/")
      --cache-source string           directory or bucket used for preloading the cache
      --debug                         enable test debug logging (default true)
  -d, --dir string                    directory to search for melange configs (default ".")
  -h, --help                          help for test
  -j, --jobs int                      number of jobs to run concurrently (default is GOMAXPROCS)
  -k, --keyring-append strings        path to extra keys to include in the build environment keyring (default [https://packages.wolfi.dev/os/wolfi-signing.rsa.pub])
      --pipeline-dir string           directory used to extend defined built-in pipelines (default "./pipelines")
  -r, --repository-append strings     path to extra repositories to include in the build environment (default [https://packages.wolfi.dev/os])
      --runner string                 which runner to use to enable running commands, default is based on your platform. (default "docker")
      --test-package-append strings   extra packages to install for each of the test environments (default [wolfi-base])
      --trace string                  where to write trace output
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "INFO")
```

### SEE ALSO

* [wolfictl](wolfictl.md)	 - A CLI helper for developing Wolfi

