## wolfictl vex

Tools to generate VEX statements for Wolfi packages and images

### Synopsis

wolfictl vex: Tools to generate VEX statements for Wolfi packages and images
		
The vex family of subcommands interacts with Wolfi data and configuration
files to generate Vulnerability Exploitability eXchange (VEX) documents to
inform downstream consumer how vulnerabilities impact Wolfi packages and images
that use them. 

wolfictl can generate VEX data by reading the melange configuration files
of each package and additional information coming from external documents.
There are currently two VEX subcommands:

 wolfictl vex package: Generates VEX documents from a list of melange configs

 wolfictl vex sbom: Generates a VEX document by reading an image SBOM

For more information please see the help sections if these subcommands. To know
more about the VEX tooling powering wolfictl see: https://openvex.dev/




### Options

```
  -h, --help   help for vex
```

### SEE ALSO

* [wolfictl](wolfictl.md)	 - A CLI helper for developing Wolfi
* [wolfictl vex package](wolfictl_vex_package.md)	 - Generate a VEX document from package configuration files
* [wolfictl vex sbom](wolfictl_vex_sbom.md)	 - Generate a VEX document from wolfi packages listed in an SBOM

