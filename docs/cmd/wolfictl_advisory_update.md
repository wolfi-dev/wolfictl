## wolfictl advisory update

append an entry to an existing package advisory

### Usage

```
wolfictl advisory update
```

### Synopsis

append an entry to an existing package advisory

### Options

```
      --action string                                      action statement for VEX statement (used only for affected status)
  -a, --advisories-repo-dir WOLFICTL_ADVISORIES_REPO_DIR   directory containing the advisories repository (can also be set with environment variable WOLFICTL_ADVISORIES_REPO_DIR)
      --arch strings                                       package architectures to find published versions for (default [x86_64,aarch64])
  -d, --distro-repo-dir WOLFICTL_DISTRO_REPO_DIR           directory containing the distro repository (can also be set with environment variable WOLFICTL_DISTRO_REPO_DIR)
      --fixed-version string                               package version where fix was applied (used only for fixed status)
  -h, --help                                               help for update
      --impact string                                      impact statement for VEX statement (used only for not_affected status)
      --justification string                               justification for VEX statement (used only for not_affected status)
      --no-distro-detection                                do not attempt to auto-detect the distro
      --no-prompt                                          do not prompt the user for input
  -p, --package string                                     package name
  -r, --package-repo-url string                            URL of the APK package repository
  -s, --status string                                      status for VEX statement
      --timestamp string                                   timestamp for VEX statement (default "now")
  -V, --vuln string                                        vulnerability ID for advisory
```

### SEE ALSO

* [wolfictl advisory](wolfictl_advisory.md)	 - Utilities for viewing and modifying Wolfi advisory data

