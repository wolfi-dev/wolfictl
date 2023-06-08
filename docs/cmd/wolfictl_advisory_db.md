## wolfictl advisory db

Build a security database from advisory data (NOTE: For now, this command uses secfixes data, but will soon use advisory data instead.)

### Usage

```
wolfictl advisory db
```

### Synopsis

Build a security database from advisory data (NOTE: For now, this command uses secfixes data, but will soon use advisory data instead.)

### Options

```
  -a, --advisories-repo-dir strings   directory containing an advisories repository
      --arch strings                  the package architectures the security database is for (default [x86_64])
  -h, --help                          help for db
      --no-distro-detection           do not attempt to auto-detect the distro
  -o, --output string                 output location (default: stdout)
      --repo string                   the name of the package repository (default "os")
      --url-prefix string             URL scheme and hostname for the package repository (default "https://packages.wolfi.dev")
```

### SEE ALSO

* [wolfictl advisory](wolfictl_advisory.md)	 - Utilities for viewing and modifying Wolfi advisory data

