## wolfictl advisory list

List advisories for specific packages, vulnerabilities, or the entire data set

***Aliases**: ls*

### Usage

```
wolfictl advisory list
```

### Synopsis

List advisories for specific packages, vulnerabilities, or the entire data set.

The 'list' (or 'ls') command prints a list of advisories based on the given 
selection criteria. By default, all advisories in the current advisory data set 
will be listed.

FILTERING

You can list advisories for a single package:

	wolfictl adv ls -p glibc

You can list all advisories for a given vulnerability ID across all packages:

	wolfictl adv ls -V CVE-2023-38545

You can show only advisories that are considered not to be "resolved":

	wolfictl adv ls --unresolved

And you can combine the above flags as needed.

HISTORY

Using the --history flag, you can list advisory events instead of just 
advisories' latest states. This is useful for viewing a summary of an 
investigation over time for a given package/vulnerability match.'


### Options

```
  -a, --advisories-repo-dir string   directory containing the advisories repository
  -h, --help                         help for list
      --history                      show full history for advisories
      --no-distro-detection          do not attempt to auto-detect the distro
  -p, --package string               package name
      --unresolved                   only show advisories considered to be unresolved
  -V, --vuln string                  vulnerability ID for advisory
```

### SEE ALSO

* [wolfictl advisory](wolfictl_advisory.md)	 - Commands for consuming and maintaining security advisory data

