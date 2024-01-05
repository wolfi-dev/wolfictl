## wolfictl advisory secdb

Build an Alpine-style security database from advisory data

***Aliases**: db*

### Usage

```
wolfictl advisory secdb
```

### Synopsis

Build an Alpine-style security database from advisory data

### Options

```
  -a, --advisories-repo-dir strings   directory containing an advisories repository
      --arch strings                  the package architectures the security database is for (default [x86_64])
  -h, --help                          help for secdb
      --no-distro-detection           do not attempt to auto-detect the distro
  -o, --output string                 output location (default: stdout)
      --repo string                   the name of the package repository (default "os")
      --url-prefix string             URL scheme and hostname for the package repository (default "https://packages.wolfi.dev")
```

### SEE ALSO

* [wolfictl advisory](wolfictl_advisory.md)	 - Commands for consuming and maintaining security advisory data

