## wolfictl advisory update

Update an existing advisory with a new event

### Usage

```
wolfictl advisory update [flags]
```

### Synopsis

Update an existing advisory with a new event.

Use this command to update an existing advisory by adding a new "event" to the
advisory, i.e. when the given package/vulnerability combination already exists
in the advisories repo. If the package/vulnerability combination doesn't yet
exist, use the "create" command instead.

This command will prompt for all required fields, and will attempt to fill in
as many optional fields as possible. You can abort the advisory update at any
point in the prompt by pressing Ctrl+C.

You can specify required values on the command line using the flags relevant to
the advisory event you are adding. If not all required values are provided on
the command line, the command will prompt for the missing values.

It's possible to update advisories for multiple packages and/or vulnerabilities
at once by using a comma-separated list of package names and vulnerabilities.
This is available for both the CLI flags and the interactive prompt fields.

When performing a bulk operation (i.e. on multiple advisories at once), if an
advisory already has an event of the same type as the one being added, that
advisory will be skipped, and a warning will be logged. This is to prevent
adding redundant events to advisories that already have the same type of event.

If the --no-prompt flag is specified, then the command will fail if any
required fields are missing.

### Options

```
  -a, --advisories-repo-dir string   directory containing the advisories repository
      --arch strings                 package architectures to find published versions for (default [x86_64,aarch64])
  -d, --distro-repo-dir string       directory containing the distro repository
      --fixed-version string         package version where fix was applied (used only for 'fixed' event type)
      --fp-type string               type of false positive [vulnerability-record-analysis-contested, component-vulnerability-mismatch, vulnerable-code-version-not-used, vulnerable-code-not-included-in-package, vulnerable-code-not-in-execution-path, vulnerable-code-cannot-be-controlled-by-adversary, inline-mitigations-exist]
  -h, --help                         help for update
      --no-distro-detection          do not attempt to auto-detect the distro
      --no-prompt                    do not prompt the user for input
      --note string                  prose explanation to attach to the event data (can be used with any event type)
  -p, --package strings              package names
  -r, --package-repo-url string      URL of the APK package repository
      --timestamp string             timestamp of the event (RFC3339 format) (default "now")
  -t, --type string                  type of event [detection, true-positive-determination, fixed, false-positive-determination, analysis-not-planned, fix-not-planned, pending-upstream-fix]
  -V, --vuln strings                 vulnerability IDs for advisory
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "WARN")
```

### SEE ALSO

* [wolfictl advisory](wolfictl_advisory.md)	 - Commands for consuming and maintaining security advisory data

