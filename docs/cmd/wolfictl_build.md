## wolfictl build



### Usage

```
wolfictl build
```

### Synopsis



### Options

```
      --arch strings                    arch of package to build (default [x86_64,aarch64])
      --cache-dir string                directory used for cached inputs (default "./melange-cache/")
      --cache-source string             directory or bucket used for preloading the cache
      --destination-repository string   repo used to check for (and skip) existing packages
  -d, --dir string                      directory to search for melange configs (default ".")
      --dry-run                         print commands instead of executing them
      --generate-index                  whether to generate APKINDEX.tar.gz (default true)
  -h, --help                            help for build
  -j, --jobs int                        number of jobs to run concurrently (default is GOMAXPROCS)
  -k, --keyring-append strings          path to extra keys to include in the build environment keyring (default [https://packages.wolfi.dev/os/wolfi-signing.rsa.pub])
      --namespace string                namespace to use in package URLs in SBOM (eg wolfi, alpine) (default "wolfi")
      --out-dir string                  directory where packages will be output
      --pipeline-dir string             directory used to extend defined built-in pipelines
  -r, --repository-append strings       path to extra repositories to include in the build environment (default [https://packages.wolfi.dev/os])
      --runner string                   which runner to use to enable running commands, default is based on your platform. (default "docker")
      --signing-key string              key to use for signing
      --summary string                  file to write build summary
      --trace string                    where to write trace output
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "INFO")
```

### SEE ALSO

* [wolfictl](wolfictl.md)	 - A CLI helper for developing Wolfi

