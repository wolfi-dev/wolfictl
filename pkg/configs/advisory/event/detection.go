package event

import (
	"time"

	"github.com/facebookincubator/nvdtools/wfn"
)

// Detection is an event that indicates that a potential vulnerability was
// detected for a distro package.
type Detection struct {
	// Detector identifies the kind of detector that found the vulnerability match.
	Detector Detector `yaml:"detector"`

	// Subject identifies the particular software that the Detector claims is
	// vulnerable.
	Subject Subject `yaml:"subject"`

	// VulnerabilityIDs lists any known IDs of the underlying vulnerability found in
	// the Subject. This list SHOULD include a CVE ID (from NVD) if one is known.
	// Other IDs MAY be included, such as GHSA IDs or GoVulnDB IDs.
	VulnerabilityIDs []string `yaml:"vulnerability-ids"`

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

type Subject struct {
	CPE wfn.Attributes `yaml:"cpe"`

	// SBOMComponentReference *SBOMComponentReference
}

type SBOMComponentReference struct {
	SBOMKind     SBOMKind `yaml:"sbom-kind"`
	SBOMLocation string   `yaml:"sbom-location"`
	ComponentID  string   `yaml:"component-id"`
}

// SBOMKind identifies the kind of SBOM that a component reference is pointing
// to.
type SBOMKind string

const (
	SBOMKindSPDX      SBOMKind = "spdx"
	SBOMKindCycloneDX SBOMKind = "cyclonedx"
	SBOMKindSyft      SBOMKind = "syft"
)
