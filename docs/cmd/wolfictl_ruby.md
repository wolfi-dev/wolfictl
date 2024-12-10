## wolfictl ruby

Work with ruby packages

### Usage

```
wolfictl ruby [flags]
```

### Synopsis

Work with ruby packages

The ruby subcommand is intended to work with all ruby packages inside the wolfi
repo. The main uses right now are to check if the ruby version can be upgraded,
and run Github code searches for Github repos pulled from melange yaml files.

This command takes a path to the wolfi-dev/os repository as an argument. The
path can either be the directory itself to discover all files using ruby-* or
a specific melange yaml to work with.

NOTE: This is currently restricted to ruby code housed on Github as that is the
      majority. There are some on Gitlab and adding Gitlab API support is TODO.


### Examples


# Run a search query over all ruby-3.2 package in the current directory
wolfictl ruby code-search . --ruby-version 3.2 --search-term 'language:ruby racc'

# Check if all ruby-3.2 packages in the current directory can be upgraded to ruby-3.3
wolfictl ruby check-upgrade . --ruby-version 3.2 --ruby-upgrade-version 3.3


### Options

```
  -h, --help   help for ruby
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "INFO")
```

### SEE ALSO

* [wolfictl](wolfictl.md)	 - A CLI helper for developing Wolfi
* [wolfictl ruby check-upgrade](wolfictl_ruby_check-upgrade.md)	 - Check if gemspec for restricts a gem from upgrading to a specified ruby version.
* [wolfictl ruby code-search](wolfictl_ruby_code-search.md)	 - Run Github search queries for ruby packages.

