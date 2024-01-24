## wolfictl scan

Scan a package for vulnerabilities

### Usage

```
wolfictl scan [ --sbom | --build-log | --remote ] [ --advisory-filter <type> --advisories-repo-dir <path> ] target...
```

### Synopsis

This command scans one or more distro packages for vulnerabilities.

## SCANNING

There are four ways to specify the package(s) to scan:

1. Specify the path to the APK file(s) to scan.

2. Specify the path to the APK SBOM file(s) to scan. (The SBOM is expected to
   use the Syft JSON format and can be created with the "wolfictl sbom -o
   syft-json ..." command.)

3. Specify the path to a Melange build log file (or to a directory that
   contains a build log file named "packages.log"). The build log file will be
   parsed to find the APK files to scan.

4. Specify the name(s) of package(s) in the Wolfi package repository. The
   latest versions of the package(s) for all supported architectures will be
   downloaded from the Wolfi package repository and scanned.

## FILTERING

By default, the command will print all vulnerabilities found in the package(s)
to stdout. You can filter the vulnerabilities shown using existing local
advisory data. To do this, you must first clone the advisory data from the
advisories repository for the distro whose packages you are scanning. You
specify the path to each local advisories repository using the
--advisories-repo-dir flag for each repository. Then, you can use the
"--advisory-filter" flag to specify which set of advisories to use for
filtering. The following sets of advisories are available:

- "resolved": Only filter out vulnerabilities that have been resolved in the
  distro.

- "all": Filter out all vulnerabilities that are referenced from any advisory
  in the advisories repository.

- "concluded": Only filter out all vulnerabilities that have been fixed, or those
  where no change is planned to fix the vulnerability.

## AUTO-TRIAGING

Wolfictl now supports auto-triaging vulnerabilities found in Go binaries using
govulncheck. To enable this feature, use the "--govulncheck" flag. Note that
this feature is experimental and may not work in all cases. For more
information on the govulncheck utility, see
https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck. Using this feature does
not require you to install govulncheck on your system (the functionality
required is included in wolfictl as a library).

For vulnerabilities known to govulncheck, this feature annotates each
vulnerability with a "true positive" or "false positive" designation. The JSON
output mode shows more information about the govulncheck triage results than
the default outline output mode.

This feature does not filter out any results from the scan output.

This feature is only supported when scanning APKs, not when scanning SBOMs.

## OUTPUT

When a scan finishes, the command will print the results to stdout. There are
two modes of output that can be specified with the --output (or "-o") flag:

- "outline": This is the default output mode. It prints the results in a
  human-readable outline format.

- "json": This mode prints the results in JSON format. This mode is useful for
  machine processing of the results.

The command will exit with a non-zero exit code if any errors occur during the
scan.

The command will also exit with a non-zero exit code if any vulnerabilities are
found and the --require-zero flag is specified.



### Examples


# Scan a single APK file
wolfictl scan /path/to/package.apk

# Scan multiple APK files
wolfictl scan /path/to/package1.apk /path/to/package2.apk

# Scan a single SBOM file
wolfictl scan /path/to/package.sbom --sbom

# Scan a directory containing a build log file
wolfictl scan /path/to/build/log/dir --build-log

# Scan a single package in the Wolfi package repository
wolfictl scan package-name --remote

# Scan multiple packages in the Wolfi package repository
wolfictl scan package1 package2 --remote


### Options

```
  -a, --advisories-repo-dir strings   local directory for advisory data
  -f, --advisory-filter string        exclude vulnerability matches that are referenced from the specified set of advisories (resolved|all|concluded)
      --build-log                     treat input as a package build log file (or a directory that contains a packages.log file)
      --disable-sbom-cache            don't use the SBOM cache
      --distro string                 distro to use during vulnerability matching (default "wolfi")
  -h, --help                          help for scan
      --local-file-grype-db string    import a local grype db file
  -o, --output string                 output format (outline|json), defaults to outline
  -r, --remote                        treat input(s) as the name(s) of package(s) in the Wolfi package repository to download and scan the latest versions of
      --require-zero                  exit 1 if any vulnerabilities are found
  -s, --sbom                          treat input(s) as SBOM(s) of APK(s) instead of as actual APK(s)
      --use-cpes                      turn on all CPE matching in Grype
```

### SEE ALSO

* [wolfictl](wolfictl.md)	 - A CLI helper for developing Wolfi

