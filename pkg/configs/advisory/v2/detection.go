package v2

import (
	"fmt"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
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

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (d *Detection) UnmarshalYAML(v *yaml.Node) error {
	type partialDetection struct {
		Type string    `yaml:"type"`
		Data yaml.Node `yaml:"data"`
	}

	// Unmarshal the detection type and timestamp as a "partial detection" before
	// unmarshalling the detection-type-specific data.
	var partial partialDetection
	if err := v.Decode(&partial); err != nil {
		return err
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

	default:
		return fmt.Errorf("invalid detection type %q, must be one of [%s]", partial.Type, strings.Join(DetectionTypes, ", "))
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
