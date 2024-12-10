## wolfictl ruby code-search

Run Github search queries for ruby packages.

***Aliases**: cs,search*

### Usage

```
wolfictl ruby code-search [flags]
```

### Synopsis


NOTE: Due to limitations of GitHub Code Search, the search terms are only matched
      against the default branch rather than the tag from which the package is
      built. Hopefully this gets better in the future but it could lead to false
      negatives if upgrade work has been committed to the main branch but a release
      has not been cut yet.

      https://docs.github.com/en/rest/search/search?apiVersion=2022-11-28#search-code

NOTE: This is currently restricted to ruby code housed on Github as that is the
      majority. There are some on Gitlab and adding Gitlab API support is TODO.


### Examples


# Run a search query over all ruby-3.2 package in the current directory
wolfictl ruby code-search . --ruby-version 3.2 --search-terms 'language:ruby racc'


### Options

```
  -h, --help                       help for code-search
      --no-cache                   do not use cached results
  -r, --ruby-version string        ruby version to search for
  -s, --search-terms stringArray   GitHub code search term
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "INFO")
```

### SEE ALSO

* [wolfictl ruby](wolfictl_ruby.md)	 - Work with ruby packages

