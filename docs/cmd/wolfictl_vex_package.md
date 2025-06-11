## wolfictl vex package

Generate a VEX document from package configuration files

### Usage

```
wolfictl vex package CONFIG [CONFIG]... [flags]
```

### Synopsis

Generate a VEX document from package configuration files

### Examples

wolfictl vex package --author=joe@doe.com config1.yaml config2.yaml

### Options

```
      --author string   author of the VEX document
  -h, --help            help for package
      --role string     role of the author of the VEX document
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "WARN")
```

### SEE ALSO

* [wolfictl vex](wolfictl_vex.md)	 - Tools to generate VEX statements for Wolfi packages and images

