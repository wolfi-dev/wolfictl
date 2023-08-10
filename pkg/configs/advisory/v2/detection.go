package v2

import (
	"fmt"
	"slices"
	"strings"
)

const (
	DetectionTypeManual = "manual"
	DetectionTypeNVDAPI = "nvdapi"
)

var (
	// DetectionTypes is a list of all valid detection types.
	DetectionTypes = []string{
		DetectionTypeManual,
		DetectionTypeNVDAPI,
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
	if !slices.Contains(DetectionTypes, d.Type) {
		return fmt.Errorf("invalid detection type %q, must be one of [%s]", d.Type, strings.Join(DetectionTypes, ", "))
	}
	return nil
}

// DetectionNVDAPI is the data associated with DetectionTypeNVDAPI.
type DetectionNVDAPI struct {
	CPESearched string `yaml:"cpeSearched"`
	CPEFound    string `yaml:"cpeFound"`
}
