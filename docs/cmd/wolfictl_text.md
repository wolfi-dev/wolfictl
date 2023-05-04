## wolfictl text

Print a sorted list of downstream dependent packages

### Usage

```
wolfictl text
```

### Synopsis

Print a sorted list of downstream dependent packages. This will give a reliable
build order for packages. If a reliable build order is not possible, an error
will be returned.

### Options

```
  -a, --arch string       architecture to build for (default "x86_64")
  -d, --dir string        directory to search for melange configs (default ".")
  -h, --help              help for text
  -D, --show-dependents   show packages that depend on these packages, instead of these packages' dependencies
  -t, --type string       What type of text to emit; values can be one of: [target makefile name version name-version] (default "target")
```

### SEE ALSO

* [wolfictl](wolfictl.md)	 - A CLI helper for developing Wolfi
* [graph](../reference/graph.md) - The graph order resolution logic.

