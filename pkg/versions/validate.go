package versions

import (
	"errors"
	"regexp"
)

// versionRegex how to parse versions.
// see https://github.com/alpinelinux/apk-tools/blob/50ab589e9a5a84592ee4c0ac5a49506bb6c552fc/src/version.c#
var versionRegex = func() *regexp.Regexp {
	re := regexp.MustCompile(`^([0-9]+)((\.[0-9]+)*)([a-z]?)((_alpha|_beta|_pre|_rc)([0-9]*))?((_cvs|_svn|_git|_hg|_p)([0-9]*))?((-r)([0-9]+))?$`)
	re.Longest()
	return re
}

// Validate checks if the version string is a Wolfi-compatible version, and it
// returns an error if not.
//
// This is meant to check the package version WITHOUT the epoch suffix.
func Validate(v string) error {
	if !versionRegex().MatchString(v) {
		return ErrInvalidVersion
	}
	return nil
}

// ErrInvalidVersion is returned when a version string doesn't meet the
// requirements of a Wolfi-compatible version.
var ErrInvalidVersion = errors.New("not a valid Wolfi package version")
