## wolfictl advisory alias find

Query upstream data sources for aliases for the given vulnerability ID(s)

### Usage

```
wolfictl advisory alias find <vulnerability ID> [<vulnerability ID>...] [flags]
```

### Synopsis

This is a utility command to query upstream data sources to find aliases for 
the given vulnerability ID(s).

Vulnerability IDs can be CVE IDs (e.g. CVE-2021-44228) or GHSA IDs (e.g. 
GHSA-jfh8-c2jp-5v3q).

You may specify multiple vulnerability IDs at once.

If your terminal supports hyperlinks, vulnerability IDs in the output will be 
hyperlinked to the relevant webpage from the upstream data source.


### Examples


	$ wolfictl adv alias find CVE-2021-44228
	Aliases for CVE-2021-44228:
	  - GHSA-jfh8-c2jp-5v3q



	$ wolfictl adv alias find GHSA-f9jg-8p32-2f55 CVE-2020-8552
	Aliases for GHSA-f9jg-8p32-2f55:
	  - CVE-2021-25743

	Aliases for CVE-2020-8552:
	  - GHSA-82hx-w2r5-c2wq

### Options

```
  -h, --help   help for find
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "WARN")
```

### SEE ALSO

* [wolfictl advisory alias](wolfictl_advisory_alias.md)	 - Commands for discovering vulnerability aliases

