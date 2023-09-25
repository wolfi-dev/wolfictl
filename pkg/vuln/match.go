package vuln

import version "github.com/knqyf263/go-apk-version"

type Match struct {
	Package       Package
	CPESearched   CPE
	CPEFound      CPE
	Vulnerability Vulnerability
}

type Package struct {
	Name string
}

type Vulnerability struct {
	ID, URL  string
	Severity Severity
}

type CPE struct {
	URI          string
	VersionRange VersionRange
}

// VersionRange describes a continuous range of versions.
type VersionRange struct {
	// SingleVersion is populated when the VersionRange describes only a single
	// version. If this field is used, all other fields should be set to their zero
	// value.
	SingleVersion string

	VersionRangeLower          string
	VersionRangeLowerInclusive bool
	VersionRangeUpper          string
	VersionRangeUpperInclusive bool
}

// Includes returns a bool indicating whether the given version is contained
// within the VersionRange.
//
//nolint:errcheck // we expect to always have valid version ranges since we control those values
func (vr VersionRange) Includes(otherVersion string) bool {
	if vr.SingleVersion != "" {
		return vr.SingleVersion == otherVersion
	}

	other, _ := version.NewVersion(otherVersion)

	if vr.VersionRangeLower != "" {
		lower, _ := version.NewVersion(vr.VersionRangeLower)

		if vr.VersionRangeLowerInclusive {
			if lower.Equal(other) {
				return true
			}
		}

		if !lower.LessThan(other) {
			return false
		}
	}

	if vr.VersionRangeUpper != "" {
		upper, _ := version.NewVersion(vr.VersionRangeUpper)

		if vr.VersionRangeUpperInclusive {
			if upper.Equal(other) {
				return true
			}
		}

		if !upper.GreaterThan(other) {
			return false
		}
	}

	return true
}

type Severity string

const (
	SeverityUnknown  Severity = "Unknown"
	SeverityLow      Severity = "Low"
	SeverityMedium   Severity = "Medium"
	SeverityHigh     Severity = "High"
	SeverityCritical Severity = "Critical"
)
