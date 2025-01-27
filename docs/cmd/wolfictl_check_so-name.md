## wolfictl check so-name

Check so name files have not changed in upgrade

### Usage

```
wolfictl check so-name [flags]
```

### Synopsis

Check so name files have not changed in upgrade

### Options

```
      --apk-index-url string       apk-index-url used to get existing apks.  Defaults to wolfi (default "https://packages.wolfi.dev/os/aarch64/APKINDEX.tar.gz")
  -d, --directory string           directory containing melange configs (default ".")
  -h, --help                       help for so-name
      --package-list-file string   name of the package to compare (default "packages.log")
      --packages-dir string        directory containing new packages (default "packages")
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "WARN")
```

### SEE ALSO

* [wolfictl check](wolfictl_check.md)	 - Subcommands used for CI checks in Wolfi

