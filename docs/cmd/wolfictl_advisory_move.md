## wolfictl advisory move

Move a package's advisories into a new package.

***Aliases**: mv*

### Usage

```
wolfictl advisory move <old-package-name> <new-package-name>
```

### Synopsis

Move a package's advisories into a new package.

This command will move most advisories for the given package into a new package. And rename the
package to the new package name. (i.e., from foo.advisories.yaml to foo-X.Y.advisories.yaml) If the
target file already exists, the command will try to merge the advisories. To ensure the advisories
are up-to-date, the command will start a scan for the new package.

This command is also useful to start version streaming for an existing package that has not been
version streamed before. Especially that requires manual intervention to move the advisories.

The command will move the latest event for each advisory, and will update the timestamp
of the event to now. The command will not copy events of type "detection", "fixed",
"analysis_not_planned", or "fix_not_planned".


### Options

```
  -d, --dir string   directory containing the advisories to copy (default ".")
  -h, --help         help for move
```

### Options inherited from parent commands

```
      --log-level string     log level (e.g. debug, info, warn, error) (default "info")
      --log-policy strings   log policy (e.g. builtin:stderr, /tmp/log/foo) (default [builtin:stderr])
```

### SEE ALSO

* [wolfictl advisory](wolfictl_advisory.md)	 - Commands for consuming and maintaining security advisory data

