## wolfictl withdraw

Withdraw packages from an APKINDEX.tar.gz

### Usage

```
wolfictl withdraw [flags] example-pkg-1.2.3-r4
```

### Synopsis

Withdraw packages from an APKINDEX.tar.gz

### Examples

withdraw --signing-key ./foo.rsa example-pkg-1.2.3-r4 also-bad-2.3.4-r1 <old/APKINDEX.tar.gz >new/APKINDEX.tar.gz

### Options

```
  -h, --help                 help for withdraw
      --signing-key string   the signing key to use (default "melange.rsa")
```

### SEE ALSO

* [wolfictl](wolfictl.md)	 - A CLI helper for developing Wolfi

