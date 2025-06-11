## wolfictl advisory export

Export advisory data (experimental)

### Usage

```
wolfictl advisory export [flags]
```

### Synopsis

Export advisory data (experimental)

### Options

```
  -a, --advisories-repo-dir strings   directory containing an advisories repository
  -f, --format string                 Output format. One of: [yaml, csv] (default "csv")
  -h, --help                          help for export
      --no-distro-detection           do not attempt to auto-detect the distro
  -o, --output string                 output location (default: stdout). In case using OSV format this will be the output directory.
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "WARN")
```

### SEE ALSO

* [wolfictl advisory](wolfictl_advisory.md)	 - Commands for consuming and maintaining security advisory data

