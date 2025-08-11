## wolfictl withdraw

Withdraw packages from an APKINDEX.tar.gz

### Usage

```
wolfictl withdraw example-pkg-1.2.3-r4 [flags]
```

### Synopsis

Withdraw packages from an APKINDEX.tar.gz

### Examples

withdraw --signing-key ./foo.rsa example-pkg-1.2.3-r4 also-bad-2.3.4-r1 <old/APKINDEX.tar.gz >new/APKINDEX.tar.gz

### Options

```
  -h, --help                        help for withdraw
      --signing-key string          the signing key to use (default "melange.rsa")
      --withdrawn-packages string   file containing list of packages to withdraw (one per line, supports comments with #)
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "WARN")
```

### SEE ALSO

* [wolfictl](wolfictl.md)	 - A CLI helper for developing Wolfi

