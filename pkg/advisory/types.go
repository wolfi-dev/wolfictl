package advisory

import (
	"time"

	"github.com/facebookincubator/nvdtools/wfn"
)

type Advisory struct {
	ID     string  `yaml:"id"`
	Events []Event `yaml:"events"`
}

// Event is the interface that all types of advisory events implement.
type Event interface {
	Time() time.Time
}

// DetectionEvent is an event that indicates that a potential vulnerability was detected for a distro package.
type DetectionEvent struct {
	Timestamp time.Time `yaml:"timestamp"`

	// Detector identifies the kind of detector that found the vulnerability match.
	Detector Detector `yaml:"detector"`

	// Subject identifies the particular software that the Detector claims is vulnerable.
	Subject Subject

	// VulnerabilityIDs lists any known IDs of the underlying vulnerability found in
	// the Subject. This list SHOULD include a CVE ID (from NVD) if one is known.
	// Other IDs MAY be included, such as GHSA IDs or GoVulnDB IDs.
	VulnerabilityIDs []string

	// PackageVersions lists the versions of the package that the Detector claims are vulnerable.
	PackageVersions []string `yaml:"package-versions"`

	// Severity is a non-authoritative severity rating for the vulnerability. This
	// is included as a convenience, but more comprehensive severity scores SHOULD
	// be obtained from the underlying vulnerability data source(s).
	Severity Severity
}

type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var _ Event = (*DetectionEvent)(nil)

func (e DetectionEvent) Time() time.Time {
	return e.Timestamp
}

type Detector int

const (
	UnknownDetector Detector = iota
	NVDAPIDetector
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

type SBOMKind int

const (
	Unknown SBOMKind = iota
	SPDX
	CycloneDX
	Syft
)

type FalsePositiveDeterminationEvent struct {
	Timestamp time.Time
}

var _ Event = (*FalsePositiveDeterminationEvent)(nil)

func (e FalsePositiveDeterminationEvent) Time() time.Time {
	return e.Timestamp
}

type TruePositiveDeterminationEvent struct {
	Timestamp time.Time
}

var _ Event = (*TruePositiveDeterminationEvent)(nil)

func (e TruePositiveDeterminationEvent) Time() time.Time {
	return e.Timestamp
}

type FixAppliedEvent struct {
	Timestamp           time.Time
	FixedPackageVersion string
}

var _ Event = (*FixAppliedEvent)(nil)

func (e FixAppliedEvent) Time() time.Time {
	return e.Timestamp
}

type UpdatedVulnerabilityDataEvent struct {
	Timestamp time.Time
}

var _ Event = (*UpdatedVulnerabilityDataEvent)(nil)

func (e UpdatedVulnerabilityDataEvent) Time() time.Time {
	return e.Timestamp
}
