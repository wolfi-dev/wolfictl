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
      --batch                             creates a single pull request with package updates rather than individual pull request per package update
      --data-mapper-url string            URL to use for mapping packages to source update service (default "https://raw.githubusercontent.com/rawlingsj/wup-mapper/main/README.md")
      --dry-run                           prints proposed package updates rather than creating a pull request
  -h, --help                              help for update
      --package-name string               Optional: provide a specific package name to check for updates rather than searching all packages in a repo URI
      --pull-request-base-branch string   base branch to create a pull request against (default "main")
      --pull-request-title string         the title to use when creating a pull request (default "%s package update")
```

### SEE ALSO

* [wolfictl](wolfictl.md)	 - A simple CLI for working with Wolfi GitHub repositories

