package gomod

import "regexp"

var (
	pseudoVersionPattern = `^v\d+\.\d+\.\d+-\d{14}-[0-9a-f]{12}$`
	pseudoVersionRegexp  = regexp.MustCompile(pseudoVersionPattern)
)

// IsPseudoVersion reports whether the given version is a Go pseudo-version
// (https://go.dev/ref/mod#pseudo-versions).
func IsPseudoVersion(version string) bool {
	return pseudoVersionRegexp.MatchString(version)
}
