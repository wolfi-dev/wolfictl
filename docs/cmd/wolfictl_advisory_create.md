## wolfictl advisory create

Create a new advisory

### Usage

```
wolfictl advisory create [flags]
```

### Synopsis

Create a new advisory.

Use this command to create a new advisory, i.e. when the given
package/vulnerability combination doesn't already exist in the advisories repo.
If the package/vulnerability combination already exists, use the "update"
command instead.

This command will prompt for all required fields, and will attempt to fill in
as many optional fields as possible. You can abort the advisory creation at any
point in the prompt by pressing Ctrl+C.

You can specify required values on the command line using the flags relevant to
the advisory you are creating. If not all required values are provided on the
command line, the command will prompt for the missing values.

If the --no-prompt flag is specified, then the command will fail if any
required fields are missing.

This command also performs a follow-up operation to discover aliases for the
newly created advisory and any other advisories for the same package.

### Options

```
  -a, --advisories-repo-dir string   directory containing the advisories repository
      --arch strings                 package architectures to find published versions for (default [x86_64,aarch64])
  -d, --distro-repo-dir string       directory containing the distro repository
      --fixed-version string         package version where fix was applied (used only for 'fixed' event type)
      --fp-type string               type of false positive [vulnerability-record-analysis-contested, component-vulnerability-mismatch, vulnerable-code-version-not-used, vulnerable-code-not-included-in-package, vulnerable-code-not-in-execution-path, vulnerable-code-cannot-be-controlled-by-adversary, inline-mitigations-exist]
  -h, --help                         help for create
      --no-distro-detection          do not attempt to auto-detect the distro
      --no-prompt                    do not prompt the user for input
      --note string                  prose explanation to attach to the event data (can be used with any event type)
  -p, --package string               package name
  -r, --package-repo-url string      URL of the APK package repository
      --timestamp string             timestamp of the event (RFC3339 format) (default "now")
  -t, --type string                  type of event [detection, true-positive-determination, fixed, false-positive-determination, analysis-not-planned, fix-not-planned, pending-upstream-fix]
  -V, --vuln string                  vulnerability ID for advisory
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "INFO")
```

### SEE ALSO

* [wolfictl advisory](wolfictl_advisory.md)	 - Commands for consuming and maintaining security advisory data

