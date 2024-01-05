## wolfictl build



### Usage

```
wolfictl build
```

### Synopsis



### Options

```
      --arch strings                arch of package to build (default [x86_64,aarch64])
  -d, --dir string                  directory to search for melange configs (default ".")
      --dry-run                     print commands instead of executing them
  -h, --help                        help for build
  -j, --jobs int                    number of jobs to run concurrently (default is GOMAXPROCS)
  -k, --keyring-append strings      path to extra keys to include in the build environment keyring (default [https://packages.wolfi.dev/os/wolfi-signing.rsa.pub])
      --log-dir string              subdirectory where buildlogs will be written when specified (packages/$arch/buildlogs/$apk.log) (default "buildlogs")
      --pipeline-dir string         directory used to extend defined built-in pipelines
  -r, --repository-append strings   path to extra repositories to include in the build environment (default [https://packages.wolfi.dev/os])
      --runner string               which runner to use to enable running commands, default is based on your platform. (default "docker")
```

### SEE ALSO

* [wolfictl](wolfictl.md)	 - A CLI helper for developing Wolfi

