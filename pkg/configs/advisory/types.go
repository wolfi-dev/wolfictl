package advisory

import (
	"time"

	"github.com/facebookincubator/nvdtools/wfn"
)

type Advisory struct {
	ID     string  `yaml:"id"`
	Events []Event `yaml:"events"`
}

const (
	EventTypeDetection                  = "detection"
	EventTypeFalsePositiveDetermination = "false-positive-determination"
	EventTypeTruePositiveDetermination  = "true-positive-determination"
	EventTypeFixed                      = "fixed"
)

// Event is a timestamped record of new information regarding the investigation
// and resolution of a potential vulnerability match.
type Event struct {
	// Type is a string that identifies the kind of event. This field is used to
	// determine how to unmarshal the Data field.
	Type string `yaml:"type"`

	// Timestamp is the time at which the event occurred.
	Timestamp time.Time `yaml:"timestamp"`

	// Data is the event-specific data. The type of this field is determined by the
	// Type field.
	Data interface{} `yaml:"data"`
}

type Severity int

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// DetectionEvent is an event that indicates that a potential vulnerability was
// detected for a distro package.
type DetectionEvent struct {
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

func NewDetectionEvent(timestamp time.Time, event DetectionEvent) Event {
	return Event{
		Type:      EventTypeDetection,
		Timestamp: timestamp,
		Data:      event,
	}
}

type Detector string

const (
	UnknownDetector Detector = "unknown-detector"
	NVDAPIDetector  Detector = "nvd-api-detector"
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

// SBOMKind is an enum that identifies the kind of SBOM that a component
// reference is pointing to.
//
// TODO: maybe this should be a string, since order doesn't matter?
type SBOMKind int

const (
	Unknown SBOMKind = iota
	SPDX
	CycloneDX
	Syft
)

// FalsePositiveDeterminationEvent is an event that indicates that a previously
// detected vulnerability was determined to be a false positive.
type FalsePositiveDeterminationEvent struct {
}

// TruePositiveDeterminationEvent is an event that indicates that a previously
// detected vulnerability was acknowledged to be a true positive.
type TruePositiveDeterminationEvent struct {
}

// FixedEvent is an event that indicates that a vulnerability has been fixed.
type FixedEvent struct {
	FixedPackageVersion string `yaml:"fixed-package-version"`
}

func NewFixedEvent(timestamp time.Time, event FixedEvent) Event {
	return Event{
		Type:      EventTypeFixed,
		Timestamp: timestamp,
		Data:      event,
	}
}

type UpdatedVulnerabilityDataEvent struct {
}
