package event

import (
	"time"
)

// Detection is an event that indicates that a potential vulnerability was
// detected for a distro package.
type Detection struct {
	// Detector identifies the kind of detector that found the vulnerability match.
	Detector Detector `yaml:"detector"`

	// MatchTarget identifies the particular software that the Detector claims is
	// vulnerable.
	MatchTarget MatchTarget `yaml:"match-target"`

	// PackageVersions lists the versions of the package that the Detector claims
	// are vulnerable.
	PackageVersions []string `yaml:"package-versions"`

	// Vulnerability describes the vulnerability to which the package was matched.
	Vulnerability Vulnerability `yaml:"vulnerability"`
}

func NewDetection(timestamp time.Time, event Detection) Event {
	return Event{
		Type:      TypeDetection,
		Timestamp: timestamp,
		Data:      event,
	}
}

type Detector string

const (
	DetectorNVDAPI Detector = "nvd-api"
	// DetectorGrype
)

type MatchTarget struct {
	CPE string `yaml:"cpe"`

	// SBOM *SBOMComponentReference `yaml:"sbom"`
}

type Vulnerability struct {
	// Aliases lists any known IDs of this vulnerability in additional databases.
	// Each list item value should match the format of the ID field.
	Aliases []string `yaml:"aliases,omitempty"`

	// ID is the unique identifier for the vulnerability record in an upstream
	// vulnerability database. Example values are "CVE-2023-11111",
	// "GHSA-vp9c-fpxx-744v", etc.
	ID string `yaml:"id"`

	// Severity is a non-authoritative severity rating for the vulnerability. This
	// is included as a convenience, but more comprehensive severity scores SHOULD
	// be obtained from the underlying vulnerability data source(s).
	Severity Severity `yaml:"severity"`
}

// TODO: introduce these types when adding the next Detector (likely Grype).
// type SBOMComponentReference struct {
// 	Type        SBOMType `yaml:"type"`
// 	URL         string   `yaml:"url"`
// 	ComponentID string   `yaml:"component-id"`
// }
//
// // SBOMType identifies the type of SBOM that a component reference is pointing
// // to.
// type SBOMType string
//
// const (
// 	SBOMTypeSPDX      SBOMType = "spdx"
// 	SBOMTypeCycloneDX SBOMType = "cyclonedx"
// 	SBOMTypeSyft      SBOMType = "syft"
//
// 	// The SBOMTypeDynamic value instructs data consumers to look at the URL field
// 	// to find a method of deterministically producing an SBOM just-in-time that is
// 	// expected to contain a component with the provided ComponentID.
// 	SBOMTypeDynamic SBOMType = "dynamic"
// )

type Severity string

const (
	SeverityUnknown  Severity = "unknown"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)
