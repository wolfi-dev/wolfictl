## wolfictl bump

Bumps the epoch field in melange configuration files

### Usage

```
wolfictl bump config[.yaml] [config[.yaml]...] [flags]
```

### Synopsis

Bumps the epoch field in melange configuration files

The bump subcommand increments version numbers in package config files.
For now it will only bump epoch numbers but a future version will
allow users to control versions expressed in semver.

wolfictl bump can take a filename, a package or a file glob, increasing
the version in each matching configuration file:

    wolfictl bump zlib.yaml
    wolfictl bump openssl
    wolfictl bump lib*.yaml

The command assumes it is being run from the top of the wolfi/os
repository. To look for files in another location use the --repo flag.
You can use --dry-run to see which versions will be bumped without
modifying anything in the filesystem.



### Examples

wolfictl bump openssh.yaml perl lib*.yaml

### Options

```
      --dry-run       don't change anything, just print what would be done
      --epoch         bump the package epoch (default true)
  -h, --help          help for bump
      --repo string   path to the wolfi/os repository (default ".")
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "INFO")
```

### SEE ALSO

* [wolfictl](wolfictl.md)	 - A CLI helper for developing Wolfi

