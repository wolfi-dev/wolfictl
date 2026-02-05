## wolfictl advisory rebase

Apply a package’s latest advisory events to advisory data in another directory

### Usage

```
wolfictl advisory rebase <source-advisories-file-path> <destination-advisories-directory> [flags]
```

### Synopsis

Apply a package’s latest advisory events to advisory data in another directory.

Especially useful when a package's build configuration moves from one
repository to another, and you want to ensure that the advisory data for the
package is updated with the latest events from the original repository. This
helps ensure that any meaningful analysis is carried over to the new repository.

By default this command will "rebase" all advisories from the source location
onto the corresponding advisories file in the destination directory. But it's
also possible to rebase one advisory at a time, by using the -V flag to specify
a vulnerability ID or advisory ID for one particular advisory.


### Examples


wolfictl adv rebase ./argo-cd-2.8.yaml ../enterprise-advisories

wolfictl adv rebase ./argo-cd-2.8.yaml ../enterprise-advisories -V CVE-2021-25743


### Options

```
  -h, --help          help for rebase
  -V, --vuln string   vulnerability ID for advisory
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "WARN")
```

### SEE ALSO

* [wolfictl advisory](wolfictl_advisory.md)	 - Commands for consuming and maintaining security advisory data

