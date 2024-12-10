## wolfictl advisory copy

Copy a package's advisories into a new package.

***Aliases**: cp*

### Usage

```
wolfictl advisory copy <source-package-name> <destination-package-name> [flags]
```

### Synopsis

Copy a package's advisories into a new package.

This command will copy most advisories for the given package into a new package.

The command will copy the latest event for each advisory, and will update the timestamp
of the event to now. The command will not copy events of type "detection", "fixed",
"analysis_not_planned", or "fix_not_planned".


### Options

```
  -d, --dir string   directory containing the advisories to copy (default ".")
  -h, --help         help for copy
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "INFO")
```

### SEE ALSO

* [wolfictl advisory](wolfictl_advisory.md)	 - Commands for consuming and maintaining security advisory data

