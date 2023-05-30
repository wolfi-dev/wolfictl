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

// TODO: don't do this, just make CPE a string
func (s Subject) MarshalYAML() (interface{}, error) {
	wfn := s.CPE.BindToFmtString()
	return struct {
		CPE string `yaml:"cpe"`
	}{
		CPE: wfn,
	}, nil
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
