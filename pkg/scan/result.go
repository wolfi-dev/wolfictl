package scan

import (
	"sort"

	"github.com/anchore/grype/grype/db"
)

// Result represents the result of a vulnerability scan of an APK package.
type Result struct {
	// TargetAPK is the APK package that was scanned.
	TargetAPK TargetAPK

	// Findings is a list of vulnerability matches found among the component
	// packages within the APK package.
	Findings []Finding

	// Deprecated: GrypeDBStatus would be a better fit attached to a different
	// struct. The Result struct is meant for the _output_ of a scan, and it's
	// scanner _agnostic_. In contrast, the GrypeDBStatus field is scanner
	// _specific_ and is known _ahead_ of the scan. For consumers that need both the
	// scan result and the Grype DB status, it might be better to have a separate
	// struct that combines the two.
	GrypeDBStatus *db.Status
}

func (r Result) ByVuln() ByVulnResult {
	byVuln := make(map[string][]Finding)

	for i := range r.Findings {
		f := r.Findings[i]
		byVuln[f.Vulnerability.ID] = append(byVuln[f.Vulnerability.ID], f)
	}

	return ByVulnResult{
		TargetAPK: r.TargetAPK,
		ByVuln:    byVuln,
	}
}

type ByVulnResult struct {
	TargetAPK TargetAPK
	ByVuln    map[string][]Finding
}

func (r ByVulnResult) Split() []VulnFindings {
	var vfs []VulnFindings

	for vulnID, findings := range r.ByVuln {
		vfs = append(vfs, VulnFindings{
			VulnerabilityID: vulnID,
			TargetAPK:       r.TargetAPK,
			Findings:        findings,
		})
	}

	// Sort by vulnerability ID for deterministic output.
	sort.Slice(vfs, func(i, j int) bool {
		return vfs[i].VulnerabilityID < vfs[j].VulnerabilityID
	})

	return vfs
}

type VulnFindings struct {
	VulnerabilityID string
	TargetAPK       TargetAPK
	Findings        []Finding
}
