## wolfictl gh release

Performs a GitHub release using git tags to calculate the release version

### Usage

```
wolfictl gh release [flags]
```

### Synopsis

Performs a GitHub release using git tags to calculate the release version

Examples:

wolfictl gh release --bump-major
wolfictl gh release --bump-minor
wolfictl gh release --bump-patch
wolfictl gh release --bump-prerelease-with-prefix rc


### Options

```
      --bump-major                           bumps the major release version
      --bump-minor                           bumps the minor release version
      --bump-patch                           bumps the patch release version
      --bump-prerelease-with-prefix string   bumps the prerelease version using the supplied prefix, if no existing prerelease exists the patch version is also bumped to align with semantic versioning
      --dir string                           directory containing the cloned github repository to release (default ".")
  -h, --help                                 help for release
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "WARN")
```

### SEE ALSO

* [wolfictl gh](wolfictl_gh.md)	 - Commands used to interact with GitHub

