# wupdater

[![Documentation](https://godoc.org/github.com/wolfi-dev/wupdater?status.svg)](https://pkg.go.dev/mod/github.com/wolfi-dev/wupdater)
[![Go Report Card](https://goreportcard.com/badge/github.com/wolfi-dev/wupdater)](https://goreportcard.com/report/github.com/wolfi-dev/wupdater)

`wupdater` is a command line tool for working with Wolfi GitHub repositories


## Commands

See the [wupdater update command reference](https://github.com/wolfi-dev/wupdater/blob/main/docs/cmd/wupdater_update.md)

## Usage

It is expected that this CLI will be used from within a GitHub Action and interacts with the GitHub API.

This willl require `contents: read` and `pull-requests: write` permissions.  For example:

```yaml
on: [ pull_request_target ]

permissions:
  contents: read
  pull-requests: write

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: ...
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

When running outside of GitHub Actions you will need to [create a personal access token](https://github.com/settings/tokens?type=beta) with Read and Write access to code and pull requests for your target git repository that contains your melange package configs.

```bash
GITHUB_TOKEN={personal access token}
```
