## wolfictl advisory alias discover

Discover new aliases for vulnerabilities in the advisory data

### Usage

```
wolfictl advisory alias discover
```

### Synopsis

Discover new aliases for vulnerabilities in the advisory data.

This command reads the advisory data and searches for new aliases for the ID
and aliases of each advisory. For any new aliases found, the advisory data is
updated to include the new alias.

This command uses the GitHub API to query GHSA information. Note that GitHub
enforces a stricter rate limit against unauthenticated API calls. You can
authenticate this command's API calls by setting the environment variable
GITHUB_TOKEN to a personal access token, or by setting up the "gh" CLI.
When performing alias discovery across the entire data set, authenticating
these API calls is highly recommended.

You may pass one or more instances of -p/--package to have the command operate
on only one or more packages, rather than on the entire advisory data set.

Where possible, this command also normalizes advisories to use the relevant CVE
ID as the advisory ID instead of an ID from another vulnerability namespace.
This means, for example, that a non-CVE ID (e.g. a GHSA ID) that was previously
the advisory ID will be moved to the advisory's aliases if a canonical CVE ID
is discovered, since the CVE ID will become the advisory's new ID.

In cases where an advisory's ID is updated, the advisory document will be
re-sorted by advisory ID so that the resulting advisories are still sorted
correctly. Also, if updating an advisory ID results in an advisory document
having two or more advisories with the same ID, the command errors out rather
than attempting any kind of merge of the separate advisories.


### Options

```
  -a, --advisories-repo-dir string   directory containing the advisories repository
  -h, --help                         help for discover
      --no-distro-detection          do not attempt to auto-detect the distro
  -p, --package strings              packages to operate on
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "INFO")
```

### SEE ALSO

* [wolfictl advisory alias](wolfictl_advisory_alias.md)	 - Commands for discovering vulnerability aliases

