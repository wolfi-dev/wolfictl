package v2

import (
	"fmt"

	"github.com/wolfi-dev/wolfictl/pkg/versions"
)

// Fixed is an event that indicates that a vulnerability has been remediated in
// an updated version of the distribution package.
type Fixed struct {
	// FixedVersion is the version of the distribution package that contains
	// the fix to the vulnerability.
	FixedVersion string `yaml:"fixed-version"`
}

// Validate returns an error if the Fixed data is invalid.
func (f Fixed) Validate() error {
	if f.FixedVersion == "" {
		return fmt.Errorf("fixed version cannot be empty")
	}

	if err := versions.ValidateWithEpoch(f.FixedVersion); err != nil {
		return fmt.Errorf("invalid fixed version: %w", err)
	}

	return nil
}
