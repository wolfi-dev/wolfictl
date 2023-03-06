## wolfictl advisory create

create a new advisory for a package

### Usage

```
wolfictl advisory create <package-name>
```

### Synopsis

create a new advisory for a package

### Options

```
      --action string          action statement for VEX statement (used only for affected status)
      --fixed-version string   package version where fix was applied (used only for fixed status)
  -h, --help                   help for create
      --impact string          impact statement for VEX statement (used only for not_affected status)
      --justification string   justification for VEX statement (used only for not_affected status)
      --status string          status for VEX statement (default "under_investigation")
      --sync                   synchronize secfixes data immediately after creating advisory
      --timestamp string       timestamp for VEX statement (default "now")
      --vuln string            vulnerability ID for advisory
```

### SEE ALSO

* [wolfictl advisory](wolfictl_advisory.md)	 - Utilities for viewing and modifying Wolfi advisory data

