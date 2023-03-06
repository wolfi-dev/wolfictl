## wolfictl update package

Proposes a single melange package update via a pull request

### Usage

```
wolfictl update package
```

### Synopsis

"Proposes a single melange package update via a pull request".

### Examples

wolfictl update package cheese --version v1.2.3 --target-repo https://github.com/wolfi-dev/os

### Options

```
      --dry-run                           prints proposed package updates rather than creating a pull request
      --epoch string                      the epoch used to identify fix, defaults to 0 as this command is expected to run in a release pipeline that's creating a new version so epoch will be 0 (default "0")
  -h, --help                              help for package
      --pull-request-base-branch string   base branch to create a pull request against (default "main")
      --sec-fixes fixes: CVE###           checks commit messages since last release, for fixes: CVE### and generates melange security advisories (default true)
      --target-repo string                target git repository containing melange configuration to update (default "https://github.com/wolfi-dev/os")
      --use-gitsign                       enable gitsign to sign the git commits
      --version string                    version to bump melange package to
```

### SEE ALSO

* [wolfictl update](wolfictl_update.md)	 - Proposes melange package update(s) via a pull request

