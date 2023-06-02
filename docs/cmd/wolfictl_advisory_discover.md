## wolfictl advisory discover

search for new potential vulnerabilities and create advisories for them

### Usage

```
wolfictl advisory discover
```

### Synopsis

search for new potential vulnerabilities and create advisories for them

### Options

```
  -a, --advisories-repo-dir WOLFICTL_ADVISORIES_REPO_DIR   directory containing the advisories repository (can also be set with environment variable WOLFICTL_ADVISORIES_REPO_DIR)
  -d, --distro-repo-dir WOLFICTL_DISTRO_REPO_DIR           directory containing the distro repository (can also be set with environment variable WOLFICTL_DISTRO_REPO_DIR)
  -h, --help                                               help for discover
      --no-distro-detection                                do not attempt to auto-detect the distro
      --nvd-api-key string                                 NVD API key (Can also be set via the environment variable 'WOLFICTL_NVD_API_KEY'. Using an API key significantly increases the rate limit for API requests. If you need an NVD API key, go to https://nvd.nist.gov/developers/request-an-api-key .)
  -p, --package string                                     package name
  -r, --package-repo-url string                            URL of the APK package repository
```

### SEE ALSO

* [wolfictl advisory](wolfictl_advisory.md)	 - Utilities for viewing and modifying Wolfi advisory data

