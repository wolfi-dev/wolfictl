## wolfictl advisory update

append an entry to an existing package advisory

### Usage

```
wolfictl advisory update <package-name>
```

### Synopsis

append an entry to an existing package advisory

### Options

```
      --action string          action statement for VEX statement (used only for affected status)
      --fixed-version string   package version where fix was applied (used only for fixed status)
  -h, --help                   help for update
      --impact string          impact statement for VEX statement (used only for not_affected status)
      --justification string   justification for VEX statement (used only for not_affected status)
      --status string          status for VEX statement
      --sync                   synchronize secfixes data immediately after updating advisory
      --timestamp string       timestamp for VEX statement (default "now")
      --vuln string            vulnerability ID for advisory
```

### SEE ALSO

* [wolfictl advisory](wolfictl_advisory.md)	 - Utilities for viewing and modifying Wolfi advisory data

