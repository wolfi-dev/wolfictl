package versions

import (
	"errors"
	"regexp"
)

var (
	// versionRegex how to parse versions.
	// see https://github.com/alpinelinux/apk-tools/blob/50ab589e9a5a84592ee4c0ac5a49506bb6c552fc/src/version.c#
	versionRegex = func() *regexp.Regexp {
		re := regexp.MustCompile(`^([0-9]+)((\.[0-9]+)*)([a-z]?)((_alpha|_beta|_pre|_rc)([0-9]*))?((_cvs|_svn|_git|_hg|_p)([0-9]*))?((-r)([0-9]+))?$`)
		re.Longest()
		return re
	}()

	// versionWithEpochRegex how to parse versions that include the epoch suffix.
	versionWithEpochRegex = func() *regexp.Regexp {
		re := regexp.MustCompile(`^([0-9]+)((\.[0-9]+)*)([a-z]?)((_alpha|_beta|_pre|_rc)([0-9]*))?((_cvs|_svn|_git|_hg|_p)([0-9]*))?((-r)([0-9]+))?(-r[0-9]+)$`)
		re.Longest()
		return re
	}()
)

var (
	// ErrInvalidVersion is returned when a version string doesn't meet the
	// requirements of a Wolfi-compatible version.
	ErrInvalidVersion = errors.New("not a valid Wolfi package version")

	// ErrInvalidFullVersion is returned when a version string doesn't meet the
	// requirements of a Wolfi-compatible "full" version (which should include the
	// epoch suffix).
	ErrInvalidFullVersion = errors.New("not a valid full Wolfi package version (with epoch)")
)

// ValidateWithoutEpoch checks if the given package version, which is expected
// NOT to include the epoch component, is a Wolfi-compatible version. It returns
// an error if not.
func ValidateWithoutEpoch(v string) error {
	if !versionRegex.MatchString(v) {
		return ErrInvalidVersion
	}
	return nil
}

// ValidateWithEpoch checks if the given package version, which is expected to
// include the epoch component, is a Wolfi-compatible "full" version. It returns
// an error if not.
func ValidateWithEpoch(v string) error {
	if !versionWithEpochRegex.MatchString(v) {
		return ErrInvalidFullVersion
	}
	return nil
}
