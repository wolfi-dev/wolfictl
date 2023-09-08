## wolfictl advisory list

list advisories for specific packages or across all of Wolfi

### Usage

```
wolfictl advisory list
```

### Synopsis

list advisories for specific packages or across all of Wolfi

### Options

```
  -a, --advisories-repo-dir WOLFICTL_ADVISORIES_REPO_DIR   directory containing the advisories repository (can also be set with environment variable WOLFICTL_ADVISORIES_REPO_DIR)
  -h, --help                                               help for list
      --history                                            show full history for advisories
      --no-distro-detection                                do not attempt to auto-detect the distro
  -p, --package string                                     package name
      --unresolved                                         only show advisories whose latest status is affected or under_investigation
  -V, --vuln string                                        vulnerability ID for advisory
```

### SEE ALSO

* [wolfictl advisory](wolfictl_advisory.md)	 - Utilities for viewing and modifying Wolfi advisory data

