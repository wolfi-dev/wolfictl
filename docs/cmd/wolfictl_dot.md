## wolfictl dot

Generate graphviz .dot output

### Usage

```
wolfictl dot
```

### Synopsis


Generate .dot output and pipe it to dot to generate an SVG

  wolfictl dot | dot -Tsvg > graph.svg

Generate .dot output and pipe it to dot to generate a PNG

  wolfictl dot | dot -Tpng > graph.png


### Options

```
  -d, --dir string        directory to search for melange configs (default ".")
  -h, --help              help for dot
  -D, --show-dependents   show packages that depend on these packages, instead of these packages' dependencies
```

### SEE ALSO

* [wolfictl](wolfictl.md)	 - A CLI helper for developing Wolfi

