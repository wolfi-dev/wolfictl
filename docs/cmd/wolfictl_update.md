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
      --data-mapper-url string            URL to use for mapping packages to source update service (default "https://raw.githubusercontent.com/wolfi-dev/wolfi-update-mapper/main/DATA.md")
      --dry-run                           prints proposed package updates rather than creating a pull request
      --github-release-query              query the GitHub graphql API for latest releases (default true)
  -h, --help                              help for update
      --package-name stringArray          Optional: provide a specific package name to check for updates rather than searching all packages in a repo URI
      --pull-request-base-branch string   base branch to create a pull request against (default "main")
      --pull-request-title string         the title to use when creating a pull request (default "%s/%s package update")
      --release-monitoring-query          query https://release-monitoring.org/ API for latest releases (default true)
```

### SEE ALSO

* [wolfictl](wolfictl.md)	 - A simple CLI for working with Wolfi GitHub repositories
* [wolfictl update package](wolfictl_update_package.md)	 - Proposes a single melange package update via a pull request

