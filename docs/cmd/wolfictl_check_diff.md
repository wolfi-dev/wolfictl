## wolfictl check diff

Create a diff comparing proposed apk changes following a melange build, to the latest available in an APKINDEX

### Usage

```
wolfictl check diff
```

### Synopsis

Create a diff comparing proposed apk changes following a melange build, to the latest available in an APKINDEX

### Options

```
      --apk-index-url string       apk-index-url used to get existing apks.  Defaults to wolfi (default "https://packages.wolfi.dev/os/%s/APKINDEX.tar.gz")
      --dir string                 directory the command is executed from and will contain the resulting diff.log file (default "/Users/jason/git/wolfictl")
  -h, --help                       help for diff
      --package-list-file string   name of the package to compare (default "packages.log")
      --packages-dir string        directory containing new packages (default "/Users/jason/git/wolfictl/packages")
```

### SEE ALSO

* [wolfictl check](wolfictl_check.md)	 - Subcommands used for CI checks in Wolfi

