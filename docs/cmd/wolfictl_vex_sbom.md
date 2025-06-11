## wolfictl vex sbom

Generate a VEX document from wolfi packages listed in an SBOM

### Usage

```
wolfictl vex sbom [flags] sbom.spdx.json
```

### Synopsis

wolfictl vex sbom: Generate a VEX document from wolfi packages listed in an SBOM

The vex sbom subcommand generates VEX documents describing how vulnerabilities
impact Wolfi packages listed in an SBOM. This subcommand reads SPDX SBOMs and
will recognize and capture all packages identified as Wolfi OS components
by its purl. For example, if an SBOM contains a package with the following
purl:

	pkg:apk/wolfi/curl@7.87.0-r0

wolfictl will read the melange configuration file that created the package and
create a VEX document containing impact assessments in its advisories.

wolfictl will read the melange config files from an existing wolfi-dev/os clone
or, if not specified, it will clone the repo for you.


### Examples

wolfictl vex sbom --author=joe@doe.com sbom.spdx.json

### Options

```
      --author string   author of the VEX document
  -h, --help            help for sbom
      --repo string     path to a local clone of the wolfi-dev/os repo
      --role string     role of the author of the VEX document
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "WARN")
```

### SEE ALSO

* [wolfictl vex](wolfictl_vex.md)	 - Tools to generate VEX statements for Wolfi packages and images

