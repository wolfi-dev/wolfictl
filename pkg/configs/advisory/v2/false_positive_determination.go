package v2

import (
	"fmt"
	"slices"
	"strings"
)

const (
	// FPTypeVulnerabilityRecordAnalysisContested indicates that the distro
	// maintainers view the vulnerability record itself to be describing a behavior
	// that is not a security concern or that misattributes security fault to the
	// software in the distro package.
	//
	// VEX compatibility note: this type should be mapped to the
	// "vulnerable_code_not_present" justification.
	FPTypeVulnerabilityRecordAnalysisContested = "vulnerability-record-analysis-contested"

	// FPTypeComponentVulnerabilityMismatch indicates that the component referred to
	// by the vulnerability record is not the component found in the distribution
	// package. (For example, perhaps a vulnerability scanner found a vulnerability
	// for a package with the same name, but for a different language ecosystem.)
	//
	// VEX compatibility note: this type should be mapped to the
	// "component_not_present" justification.
	FPTypeComponentVulnerabilityMismatch = "component-vulnerability-mismatch"

	// FPTypeVulnerableCodeVersionNotUsed indicates that the vulnerability was
	// correctly matched to the component, except that the version(s) of the
	// component referred to by the vulnerability record have never been present in
	// a release of the distribution package.
	//
	// VEX compatibility note: this type should be mapped to the
	// "vulnerable_code_not_present" justification.
	FPTypeVulnerableCodeVersionNotUsed = "vulnerable-code-version-not-used"

	// FPTypeVulnerableCodeNotIncludedInPackage indicates that the vulnerable code
	// (e.g. a particular function) may have been available for use or retrieved
	// during the package build process but ultimately was not included in the
	// distro package.
	//
	// VEX compatibility note: this type should be mapped to the
	// "vulnerable_code_not_present" justification.
	FPTypeVulnerableCodeNotIncludedInPackage = "vulnerable-code-not-included-in-package"

	// FPTypeVulnerableCodeNotInExecutionPath indicates that the vulnerable code (e.g.
	// a particular function) is present in the package, but it is impossible for
	// this code to be executed in the package.
	//
	// VEX compatibility note: this type should be mapped to the
	// "vulnerable_code_not_in_execute_path" justification.
	FPTypeVulnerableCodeNotInExecutionPath = "vulnerable-code-not-in-execution-path"

	// FPTypeVulnerableCodeCannotBeControlledByAdversary indicates that the
	// vulnerable code is present and able to be executed, but not in a way that can
	// be exploited by an adversary.
	//
	// VEX compatibility note: this type should be mapped to the
	// "vulnerable_code_cannot_be_controlled_by_adversary" justification.
	FPTypeVulnerableCodeCannotBeControlledByAdversary = "vulnerable-code-cannot-be-controlled-by-adversary"

	// FPTypeInlineMitigationsExist indicates that the vulnerable code is present
	// and able to be exploited by an adversary, but that the vulnerability is
	// mitigated by other code in the package.
	//
	// VEX compatibility note: this type should be mapped to the
	// "inline_mitigations_already_exist" justification.
	FPTypeInlineMitigationsExist = "inline-mitigations-exist"
)

var FPTypes = []string{
	FPTypeVulnerabilityRecordAnalysisContested,
	FPTypeComponentVulnerabilityMismatch,
	FPTypeVulnerableCodeVersionNotUsed,
	FPTypeVulnerableCodeNotIncludedInPackage,
	FPTypeVulnerableCodeNotInExecutionPath,
	FPTypeVulnerableCodeCannotBeControlledByAdversary,
	FPTypeInlineMitigationsExist,
}

// FalsePositiveDetermination is an event that indicates that a previously
// detected vulnerability was determined to be a false positive.
type FalsePositiveDetermination struct {
	Type string `yaml:"type"`
	Note string `yaml:"note,omitempty"`
}

func (fp FalsePositiveDetermination) Validate() error {
	if !slices.Contains(FPTypes, fp.Type) {
		return fmt.Errorf("invalid false positive determination type %q, must be one of [%s]", fp.Type, strings.Join(FPTypes, ", "))
	}

	return nil
}
