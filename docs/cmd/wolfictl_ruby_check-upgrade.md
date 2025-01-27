## wolfictl ruby check-upgrade

Check if gemspec for restricts a gem from upgrading to a specified ruby version.

***Aliases**: cu*

### Usage

```
wolfictl ruby check-upgrade [flags]
```

### Synopsis


NOTE: This is currently restricted to ruby code housed on Github as that is the
      majority. There are some on Gitlab and adding Gitlab API support is TODO.


### Examples


# Check if all ruby-3.2 packages in the current directory can be upgraded to ruby-3.3
wolfictl ruby check-upgrade . --ruby-version 3.2 --ruby-upgrade-version 3.3


### Options

```
  -h, --help                          help for check-upgrade
      --no-cache                      do not use cached results
  -u, --ruby-upgrade-version string   ruby version to check for updates
  -r, --ruby-version string           ruby version to search for
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "WARN")
```

### SEE ALSO

* [wolfictl ruby](wolfictl_ruby.md)	 - Work with ruby packages

