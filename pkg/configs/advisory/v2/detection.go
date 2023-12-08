package v2

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/wolfi-dev/wolfictl/pkg/internal/errorhelpers"
	"github.com/wolfi-dev/wolfictl/pkg/vuln"
	"gopkg.in/yaml.v3"
)

const (
	DetectionTypeManual = "manual"
	DetectionTypeNVDAPI = "nvdapi"
	DetectionTypeScanV1 = "scan/v1"
)

var (
	// DetectionTypes is a list of all valid detection types.
	DetectionTypes = []string{
		DetectionTypeManual,
		DetectionTypeNVDAPI,
		DetectionTypeScanV1,
	}
)

// Detection is an event that indicates that a potential vulnerability was
// detected for a distro package.
type Detection struct {
	// Type is the type of detection used to identify the vulnerability match.
	Type string `yaml:"type"`

	// Data is the data associated with the detection type.
	Data interface{} `yaml:"data,omitempty"`
}

// Validate returns an error if the Detection data is invalid.
func (d Detection) Validate() error {
	return errors.Join(
		d.validateType(),
		d.validateData(),
	)
}

func (d Detection) validateType() error {
	if !slices.Contains(DetectionTypes, d.Type) {
		return fmt.Errorf("type is %q but must be one of [%v]", d.Type, strings.Join(DetectionTypes, ", "))
	}

	return nil
}

func (d Detection) validateData() error {
	switch d.Type {
	case DetectionTypeManual:
		if d.Data != nil {
			return fmt.Errorf("data must be nil for detection type %q", d.Type)
		}

	case DetectionTypeNVDAPI:
		return validateTypedDetectionData[DetectionNVDAPI](d.Data)

	case DetectionTypeScanV1:
		return validateTypedDetectionData[DetectionScanV1](d.Data)
	}

	return nil
}

func validateTypedDetectionData[T interface{ Validate() error }](data interface{}) error {
	d, ok := data.(T)
	if !ok {
		return fmt.Errorf("data must be of type %T", new(T))
	}

	return d.Validate()
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (d *Detection) UnmarshalYAML(v *yaml.Node) error {
	type partialDetection struct {
		Type string    `yaml:"type"`
		Data yaml.Node `yaml:"data"`
	}

	// Unmarshal the detection type and timestamp as a "partial detection" before
	// unmarshalling the detection-type-specific data.
	partial, err := strictUnmarshal[partialDetection](v)
	if err != nil {
		return fmt.Errorf("strict YAML unmarshaling failed: %w", err)
	}

	// Unmarshal the detection-type-specific data.
	switch partial.Type {
	case DetectionTypeManual:
		// No data associated with this type.

	case DetectionTypeNVDAPI:
		var data DetectionNVDAPI
		if err := partial.Data.Decode(&data); err != nil {
			return err
		}
		d.Data = data

	case DetectionTypeScanV1:
		var data DetectionScanV1
		if err := partial.Data.Decode(&data); err != nil {
			return err
		}
		d.Data = data

	default:
		// TODO: log at warn level: unrecognized type
	}

	// Copy the data from the partial detection.
	d.Type = partial.Type

	return nil
}

// DetectionNVDAPI is the data associated with DetectionTypeNVDAPI.
type DetectionNVDAPI struct {
	CPESearched string `yaml:"cpeSearched"`
	CPEFound    string `yaml:"cpeFound"`
}

// Validate returns an error if the DetectionNVDAPI data is invalid.
func (d DetectionNVDAPI) Validate() error {
	return errorhelpers.LabelError("nvdapi detection data",
		errors.Join(
			errorhelpers.LabelError("cpeSearched", vuln.ValidateCPE(d.CPESearched)),
			errorhelpers.LabelError("cpeFound", vuln.ValidateCPE(d.CPEFound)),
		),
	)
}

var (
	DetectionScannerGrype = "grype"
)

var DetectionScanners = []string{
	DetectionScannerGrype,
}

// DetectionScanV1 is the data associated with DetectionTypeScanV1.
type DetectionScanV1 struct {
	SubpackageName    string `yaml:"subpackageName"`
	ComponentID       string `yaml:"componentID"` // TODO: consider namespacing this ID using the SBOM tool+format
	ComponentName     string `yaml:"componentName"`
	ComponentVersion  string `yaml:"componentVersion"`
	ComponentType     string `yaml:"componentType"`
	ComponentLocation string `yaml:"componentLocation"`
	Scanner           string `yaml:"scanner"` // TODO: it'd be nice for the scanner value to be automatically versioned
}

// Validate returns an error if the DetectionScanV1 data is invalid.
func (d DetectionScanV1) Validate() error {
	// TODO: Should SubpackageName be required, and it's set to the origin package
	// 	sometimes? Or should an empty value imply this was a scan of an origin
	// 	package?

	return errorhelpers.LabelError("scan/v1 detection data",
		errors.Join(
			errorhelpers.LabelError("componentID", validateNotEmpty(d.ComponentID)),
			errorhelpers.LabelError("componentName", validateNotEmpty(d.ComponentName)),
			errorhelpers.LabelError("componentVersion", validateNotEmpty(d.ComponentVersion)),
			errorhelpers.LabelError("componentType", validateNotEmpty(d.ComponentType)),
			errorhelpers.LabelError("componentLocation", validateNotEmpty(d.ComponentLocation)),
			errorhelpers.LabelError("scanner", validateDetectionScanner(d.Scanner)),
		),
	)
}

func validateDetectionScanner(scanner string) error {
	if !slices.Contains(DetectionScanners, scanner) {
		return fmt.Errorf("value is %q but must be one of [%v]", scanner, strings.Join(
			DetectionScanners,
			", ",
		))
	}

	return nil
}
