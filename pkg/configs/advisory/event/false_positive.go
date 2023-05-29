package event

// FalsePositiveDetermination is an event that indicates that a previously
// detected vulnerability was determined to be a false positive.
type FalsePositiveDetermination struct {
	Type  string      `yaml:"type"`
	Data  interface{} `yaml:"data"`
	Notes string      `yaml:"notes"`
}

const (
	// FPTypeVulnerabilityNotValid indicates that the vulnerability is not a valid
	// security problem. The vulnerability might be disputed or not valid for other
	// reasons.
	//
	// VEX compatibility note: this type should be mapped to the
	// "vulnerable_code_not_present" justification.
	FPTypeVulnerabilityNotValid = "vulnerability-not-valid"

	// FPTypeComponentVulnerabilityMismatch indicates that the component referred to
	// by the vulnerability record is not the component found in the distribution
	// package. (For example, perhaps a vulnerability scanner found a vulnerability
	// for a package with the same name, but for a different language ecosystem.)
	//
	// VEX compatibility note: this type should be mapped to the
	// "component_not_present" justification.
	FPTypeComponentVulnerabilityMismatch = "component-vulnerability-mismatch"

	// FPTypeNoVulnerableVersionUsed indicates that the vulnerability was correctly
	// matched to the component, except that the version(s) of the component
	// referred to by the vulnerability record have never been present in a release
	// of the distribution package.
	//
	// VEX compatibility note: this type should be mapped to the
	// "vulnerable_code_not_present" justification.
	FPTypeNoVulnerableVersionUsed = "no-vulnerable-version-used"

	// FPTypeVulnerableCodeNotPresent indicates that the vulnerable code (e.g. a
	// particular function) is not present in the package.
	//
	// VEX compatibility note: this type should be mapped to the
	// "vulnerable_code_not_present" justification.
	FPTypeVulnerableCodeNotPresent = "vulnerable-code-not-present"

	// FPTypeVulnerableCodeNotInExecutePath indicates that the vulnerable code (e.g.
	// a particular function) is present in the package, but is it positively
	// impossible for this code to be executed in the package.
	//
	// VEX compatibility note: this type should be mapped to the
	// "vulnerable_code_not_in_execute_path" justification.
	FPTypeVulnerableCodeNotInExecutePath = "vulnerable-code-not-in-execute-path"
)

type FPVulnerabilityNotValid struct {
	// References is a list of references that indicate why the vulnerability is not
	// valid.
	References []string `yaml:"references"`
}

type FPComponentVulnerabilityMismatch struct {
	// ComponentReferenceType is the type of the ComponentReference that is being used.
	ComponentReferenceType string `yaml:"component-reference-type"`

	// ComponentReference is the reference (e.g. a package URL) to the component to
	// which the vulnerability record refers, and which is not present in this
	// package.
	ComponentReference string `yaml:"component-reference"`
}

type FPNoVulnerableVersionUsed struct {
	// VulnerableVersions is a list of versions of the component that are referred
	// to by the vulnerability record, which can be crosschecked against the list of
	// previously released versions of the distribution package to the vulnerable
	// versions were never used.
	VulnerableVersions []string `yaml:"vulnerable-versions"`
}

type FPVulnerableCodeNotPresent struct {
	// VulnerableCodeReferences is a list of references to vulnerable code that is
	// not present in the package.
	VulnerableCodeReferences []string `yaml:"vulnerable-code-references"`
}

type FPVulnerableCodeNotInExecutePath struct {
	// VulnerableCodeReferences is a list of references to vulnerable code that is
	// present in the package but never executed.
	VulnerableCodeReferences []string `yaml:"vulnerable-code-references"`
}
