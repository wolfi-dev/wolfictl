# wolfictl

[![Documentation](https://godoc.org/github.com/wolfi-dev/wolfictl?status.svg)](https://pkg.go.dev/mod/github.com/wolfi-dev/wolfictl)
[![Go Report Card](https://goreportcard.com/badge/github.com/wolfi-dev/wolfictl)](https://goreportcard.com/report/github.com/wolfi-dev/wolfictl)

`wolfictl` is a command line tool for working with Wolfi

## Installation

You can install  `wolfictl` straight from its source code. To do this, clone the git repository and then run `go install`:

```bash
# Clone the repo

git clone git@github.com:wolfi-dev/wolfictl.git wolfictl && cd $_

# Install the `wolfictl` command

go install
```

## Commands

See the [wolfictl command reference](https://github.com/wolfi-dev/wolfictl/blob/main/docs/cmd/wolfictl.md)

## Docs

[Check so_name docs](./docs/check_so_name.md) - CI check for detecting ABI breaking changes in package version updates
[Update docs](./docs/update.md) - for detecting new upstream wolfi package versions and creating a pull request to update Wolfi

## Releases

This repo is configured to automatically create weekly tagged patch releases, mainly so that it can be more easily packaged in Wolfi itself.

Releases happen Monday at 00:00 UTC, and can be manually run as necessary.
