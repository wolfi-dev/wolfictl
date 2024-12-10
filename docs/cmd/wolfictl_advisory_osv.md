## wolfictl advisory osv

Build an OSV dataset from Chainguard advisory data

### Usage

```
wolfictl advisory osv [flags]
```

### Synopsis

Build an OSV dataset from Chainguard advisory data.

This command reads advisory data from one or more directories containing Chainguard
advisory documents, and writes an OSV dataset to a local directory.

Specify directories for advisory repositories using the --advisories-repo-dir flag.

IMPORTANT: For now, the command assumes that the first listed advisory repository is the
"Wolfi" repository, and that the rest are not. In the future, we might unify all advisory
repositories into a single collection of all advisory documents, and remove the need for
multiple advisory repositories.

The user must also specify directories for all package repositories associated with the
given advisory data. This is used to make sure the OSV data includes all relevant packages
and subpackages.

The output directory for the OSV dataset is specified using the --output flag. This
directory must already exist before running the command.


### Options

```
  -a, --advisories-repo-dir strings   path to the directory(ies) containing Chainguard advisory data
  -h, --help                          help for osv
  -o, --output string                 path to a local directory in which the OSV dataset will be written
  -p, --packages-repo-dir strings     path to the directory(ies) containing Chainguard package data
  -v, --verbose count                 logging verbosity (v = info, vv = debug, default is none)
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "INFO")
```

### SEE ALSO

* [wolfictl advisory](wolfictl_advisory.md)	 - Commands for consuming and maintaining security advisory data

