## wolfictl update

Proposes melange package update(s) via a pull request

### Usage

```
wolfictl update
```

### Synopsis

Proposes melange package update(s) via a pull request

### Options

```
      --create-issues                     creates GitHub Issues for failed package updates (default true)
      --dry-run                           prints proposed package updates rather than creating a pull request
      --github-labels stringArray         Optional: provide a list of labels to apply to updater generated issues and pull requests
      --github-release-query              query the GitHub graphql API for latest releases (default true)
  -h, --help                              help for update
      --max-retries int                   maximum number of retries for failed package updates (default 3)
      --package-name stringArray          Optional: provide a specific package name to check for updates rather than searching all packages in a repo URI
      --path string                       path in the git repo containing the melange yaml files
      --pull-request-base-branch string   base branch to create a pull request against (default "main")
      --pull-request-title string         the title to use when creating a pull request (default "%s/%s package update")
      --release-monitoring-query          query https://release-monitoring.org/ API for latest releases (default true)
      --use-gitsign                       enable gitsign to sign the git commits
```

### SEE ALSO

* [wolfictl](wolfictl.md)	 - A CLI helper for developing Wolfi
* [wolfictl update package](wolfictl_update_package.md)	 - Proposes a single melange package update via a pull request

