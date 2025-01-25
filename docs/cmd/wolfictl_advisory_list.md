## wolfictl advisory list

List advisories for specific packages, vulnerabilities, or the entire data set

***Aliases**: ls*

### Usage

```
wolfictl advisory list [flags]
```

### Synopsis

List advisories for specific packages, vulnerabilities, or the entire data set.

The 'list' (or 'ls') command prints a table of advisories based on the given 
selection criteria. By default, all advisories in the current advisory data set 
will be listed.

FILTERING

You can list advisories for a single package:

	wolfictl adv ls -p glibc

You can list all advisories for a given vulnerability ID across all packages:

	wolfictl adv ls -V CVE-2023-38545

You can filter advisories by the type of the latest event:

	wolfictl adv ls -t detection

You can filter advisories by the detected component type:

	wolfictl adv ls -c python

You can filter advisories by the date they were created or last updated:

	wolfictl adv ls --created-since 2024-01-01
	wolfictl adv ls --created-before 2023-12-31
	wolfictl adv ls --updated-since 2024-06-01
	wolfictl adv ls --updated-before 2024-06-01

You can show only advisories that are considered not to be "resolved":

	wolfictl adv ls --unresolved

And you can combine the above flags as needed.

HISTORY

Using the --history flag, you can list advisory events instead of just 
advisories' latest states. This is useful for viewing a summary of an 
investigation over time for a given package/vulnerability match.'

OUTPUT FORMAT

Using the --output (-o) flag, you can select the output format used to render
the results. By default, results are rendered as a "table"; however, you can
also select "json".

COUNT

You get a count of the advisories that match the criteria by using the --count
flag. This will report just the count, not the full list of advisories.

    wolfictl adv ls <various filter flags> --count



### Options

```
  -a, --advisories-repo-dir string   directory containing the advisories repository
      --aliases                      show other known vulnerability IDs for each advisory (default true)
  -c, --component-type string        filter advisories by detected component type
      --count                        show only the count of advisories that match the criteria
      --created-before string        filter advisories created before a given date
      --created-since string         filter advisories created since a given date
  -h, --help                         help for list
      --history                      show full history for advisories
  -o, --output string                output format (table|json), defaults to table
  -p, --package string               package name
  -t, --type string                  filter advisories by event type
      --unresolved                   only show advisories considered to be unresolved
      --updated-before string        filter advisories updated before a given date
      --updated-since string         filter advisories updated since a given date
  -V, --vuln string                  vulnerability ID for advisory
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "WARN")
```

### SEE ALSO

* [wolfictl advisory](wolfictl_advisory.md)	 - Commands for consuming and maintaining security advisory data

