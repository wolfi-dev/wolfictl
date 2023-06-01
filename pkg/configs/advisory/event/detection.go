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
	// TODO: rename to "match-target"?

	// VulnerabilityIDs lists any known IDs of the underlying vulnerability found in
	// the MatchTarget. This list SHOULD include a CVE ID (from NVD) if one is known.
	// Other IDs MAY be included, such as GHSA IDs or GoVulnDB IDs.
	VulnerabilityIDs []string `yaml:"vulnerability-ids"`
	// TODO: put under new field "vulnerability", along with things like "severity"?

	// PackageVersions lists the versions of the package that the Detector claims
	// are vulnerable.
	PackageVersions []string `yaml:"package-versions"`

	// Severity is a non-authoritative severity rating for the vulnerability. This
	// is included as a convenience, but more comprehensive severity scores SHOULD
	// be obtained from the underlying vulnerability data source(s).
	Severity Severity `yaml:"severity"`
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
	// GrypeDetector
)

type MatchTarget struct {
	CPE string `yaml:"cpe"`

	// SBOMComponentReference *SBOMComponentReference
}

type SBOMComponentReference struct {
	SBOMType     SBOMType `yaml:"sbom-type"`
	SBOMLocation string   `yaml:"sbom-location"`
	ComponentID  string   `yaml:"component-id"`
}

// SBOMType identifies the type of SBOM that a component reference is pointing
// to.
type SBOMType string

const (
	SBOMTypeSPDX      SBOMType = "spdx"
	SBOMTypeCycloneDX SBOMType = "cyclonedx"
	SBOMTypeSyft      SBOMType = "syft"
)

type Severity string

const (
	SeverityUnknown  Severity = "unknown"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)
