## wolfictl advisory validate

Validate the state of advisory data

### Usage

```
wolfictl advisory validate
```

### Synopsis

Validate the state of the advisory data.

This command examines all advisory documents to check the validity of the data.

It looks for issues like:

* Missing required fields
* Extra fields
* Enum fields with an unrecognized value
* Basic business logic checks

It also looks for issues in the _changes_ introduced by the current state of the
advisories repo, relative to a "base state" (such as the last known state of
the upstream repo's main branch). For example, it will detect if an advisory
was removed, which is not allowed.

Using distro auto-detection is the easiest way to run this command. It will
automatically detect the distro you're running, and use the correct advisory
repo URL and base hash to compare against.


If you want to run this command without distro auto-detection, you'll need to
specify the following flags:

* --no-distro-detection
* --advisories-repo-dir
* --advisories-repo-url
* --advisories-repo-base-hash
* --distro-repo-dir
* --package-repo-url

More information about these flags is shown in the documentation for each flag.

If any issues are found in the advisory data, the command will exit 1, and will
print an error message that specifies where and how the data is invalid.

### Options

```
      --advisories-repo-base-hash string   commit hash of the upstream repo to which the current state will be compared in the diff
  -a, --advisories-repo-dir string         directory containing the advisories repository
      --advisories-repo-url string         HTTPS URL of the upstream Git remote for the advisories repo
  -d, --distro-repo-dir string             directory containing the distro repository
  -h, --help                               help for validate
      --no-distro-detection                do not attempt to auto-detect the distro
  -p, --package strings                    packages to validate
  -r, --package-repo-url string            URL of the APK package repository
      --skip-alias                         skip alias completeness validation (default true)
      --skip-diff                          skip diff-based validations
      --skip-existence                     skip package configuration existence validation
  -v, --verbose count                      logging verbosity (v = info, vv = debug, default is none)
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "INFO")
```

### SEE ALSO

* [wolfictl advisory](wolfictl_advisory.md)	 - Commands for consuming and maintaining security advisory data
* [wolfictl advisory validate fixes](wolfictl_advisory_validate_fixes.md)	 - Validate fixes recorded in advisories

