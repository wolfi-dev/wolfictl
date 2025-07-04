package scan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	v2 "github.com/chainguard-dev/advisory-schema/pkg/advisory/v2"
)

// Finding represents a vulnerability finding for a single package.
type Finding struct {
	Package       Package
	Vulnerability Vulnerability
	CGAID         string `json:",omitempty"`

	// Deprecated: This field will be removed soon. Plan to use CGAID to lookup the
	// associated advisory out-of-band, instead of using this pointer.
	Advisory *v2.Advisory `json:",omitempty"`

	// Deprecated: This field will be removed soon.
	TriageAssessments []TriageAssessment `json:",omitempty"`
}

type Findings []Finding

func (f Findings) Len() int {
	return len(f)
}

func (f Findings) Less(i, j int) bool {
	fi := f[i]
	fj := f[j]

	if fi.Package.Location != fj.Package.Location {
		return fi.Package.Location < fj.Package.Location
	}

	if fi.Package.Name != fj.Package.Name {
		return fi.Package.Name < fj.Package.Name
	}

	if fi.Vulnerability.ID != fj.Vulnerability.ID {
		return fi.Vulnerability.ID < fj.Vulnerability.ID
	}

	return true
}

func (f Findings) Swap(i, j int) {
	f[i], f[j] = f[j], f[i]
}

type Package struct {
	ID       string
	Name     string
	Version  string
	Type     string
	Location string
	PURL     string
}

type Vulnerability struct {
	ID           string
	Severity     string
	Aliases      []string
	FixedVersion string
}

// Deprecated: This type will be removed soon.
type TriageAssessment struct {
	// Source is the name of the source of the triage assessment, e.g.
	// "govulncheck".
	Source string

	// TruePositive indicates whether the vulnerability is a true positive. A value
	// of false indicates that the vulnerability has been assessed to be a false
	// positive.
	TruePositive bool

	// Reason is the explanation of the triage assessment.
	Reason string
}

func mapMatchToFinding(m match.Match, vulnProvider vulnerability.Provider) (*Finding, error) {
	metadata, err := vulnProvider.VulnerabilityMetadata(m.Vulnerability.Reference)
	if err != nil {
		return nil, fmt.Errorf("retrieving metadata for vulnerability %s (%s): %w", m.Vulnerability.ID, m.Vulnerability.Namespace, err)
	}

	var relatedMetadatas []*vulnerability.Metadata
	for _, relatedRef := range m.Vulnerability.RelatedVulnerabilities {
		relatedMetadata, err := vulnProvider.VulnerabilityMetadata(relatedRef)
		if err != nil {
			return nil, fmt.Errorf("retrieving metadata for related vulnerability %s (%s): %w", relatedRef.ID, relatedRef.Namespace, err)
		}
		if relatedMetadata == nil {
			continue
		}
		relatedMetadatas = append(relatedMetadatas, relatedMetadata)
	}

	var aliases []string
	for _, rel := range relatedMetadatas {
		if rel == nil {
			continue
		}
		if rel.ID == m.Vulnerability.ID {
			// Don't count the matched vulnerability ID as its own alias. In v0.88.0, Grype
			// began listing vulnerabilities as their own related vulnerabilities, and we
			// filed a bug here: https://github.com/anchore/grype/issues/2514
			continue
		}
		aliases = append(aliases, rel.ID)
	}

	// Filter locations to only include those marked as "primary evidence"
	var locations []string
	for _, l := range m.Package.Locations.ToSlice() {
		// Check if this location has evidence annotation
		evidence, hasEvidence := l.Annotations["evidence"]

		// Include if evidence is "primary" or if no evidence annotation exists (backward compatibility)
		if !hasEvidence || evidence == "primary" {
			locations = append(locations, "/"+l.RealPath)
		}

		// Skip locations marked as some other kind of evidence (e.g., "supporting")
	}

	f := &Finding{
		Package: Package{
			ID:       string(m.Package.ID),
			Name:     m.Package.Name,
			Version:  m.Package.Version,
			Type:     string(m.Package.Type),
			Location: strings.Join(locations, ", "),
			PURL:     m.Package.PURL,
		},
		Vulnerability: Vulnerability{
			ID:           m.Vulnerability.ID,
			Severity:     metadata.Severity,
			Aliases:      aliases,
			FixedVersion: getFixedVersion(m.Vulnerability),
		},
	}

	return f, nil
}

func getFixedVersion(vuln vulnerability.Vulnerability) string {
	if vuln.Fix.State != vulnerability.FixStateFixed {
		return ""
	}

	return strings.Join(vuln.Fix.Versions, ", ")
}

// mergeRelatedFindings deduplicates findings that represent the same vulnerability
// but are reported under different IDs (e.g., CVE vs GHSA).
func mergeRelatedFindings(findings []Finding) []Finding {
	if len(findings) <= 1 {
		return findings
	}

	// Group findings by package (name, type, location)
	packageGroups := make(map[packageKey][]Finding)
	for i := range findings {
		key := packageKey{
			name:     findings[i].Package.Name,
			typ:      findings[i].Package.Type,
			location: findings[i].Package.Location,
		}
		packageGroups[key] = append(packageGroups[key], findings[i])
	}

	// Process each package group
	var result []Finding
	for _, group := range packageGroups {
		if len(group) == 1 {
			result = append(result, group[0])
			continue
		}

		// Find related findings within the package group
		merged := mergeRelatedInGroup(group)
		result = append(result, merged...)
	}

	return result
}

// packageKey is used to group findings by package
type packageKey struct {
	name     string
	typ      string
	location string
}

// mergeRelatedInGroup merges related findings within a single package group
func mergeRelatedInGroup(findings []Finding) []Finding {
	// Track which findings have been merged
	merged := make([]bool, len(findings))
	var result []Finding

	for i := 0; i < len(findings); i++ {
		if merged[i] {
			continue
		}

		// Start a new group with this finding
		group := []Finding{findings[i]}
		merged[i] = true

		// Find all related findings
		for j := i + 1; j < len(findings); j++ {
			if merged[j] {
				continue
			}

			// Check if this finding is related to any in the current group
			for k := range group {
				if findingsAreRelated(group[k], findings[j]) {
					group = append(group, findings[j])
					merged[j] = true
					break
				}
			}
		}

		// Merge the group into a single finding
		result = append(result, mergeGroup(group))
	}

	return result
}

// mergeGroup merges a group of related findings into a single finding
func mergeGroup(group []Finding) Finding {
	if len(group) == 1 {
		return group[0]
	}

	// Collect all unique aliases
	aliasSet := make(map[string]struct{})
	for i := range group {
		// Add all IDs and aliases to the set
		aliasSet[group[i].Vulnerability.ID] = struct{}{}
		for _, alias := range group[i].Vulnerability.Aliases {
			aliasSet[alias] = struct{}{}
		}
	}

	// Choose the representative finding (prefer GHSA > CVE > others)
	representative := selectRepresentative(group)

	// Remove the representative's ID from the alias set
	delete(aliasSet, representative.Vulnerability.ID)

	// Convert alias set to sorted slice
	var aliases []string
	for alias := range aliasSet {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)

	// Update the representative with all aliases
	representative.Vulnerability.Aliases = aliases
	return representative
}

// selectRepresentative chooses which finding to keep as the representative
func selectRepresentative(findings []Finding) Finding {
	// First, prefer the finding with the most aliases
	maxAliases := -1
	var candidates []Finding

	for i := range findings {
		aliasCount := len(findings[i].Vulnerability.Aliases)
		if aliasCount > maxAliases {
			maxAliases = aliasCount
			candidates = []Finding{findings[i]}
		} else if aliasCount == maxAliases {
			candidates = append(candidates, findings[i])
		}
	}

	// Among candidates with equal alias counts, prefer GHSA > CVE > others
	for i := range candidates {
		if strings.HasPrefix(candidates[i].Vulnerability.ID, "GHSA-") {
			return candidates[i]
		}
	}
	for i := range candidates {
		if strings.HasPrefix(candidates[i].Vulnerability.ID, "CVE-") {
			return candidates[i]
		}
	}

	// Return the first candidate if no preference matches
	return candidates[0]
}

// createAliasSet returns a set containing the vulnerability ID and all aliases
func createAliasSet(f Finding) map[string]struct{} {
	set := make(map[string]struct{})
	set[f.Vulnerability.ID] = struct{}{}
	for _, alias := range f.Vulnerability.Aliases {
		set[alias] = struct{}{}
	}
	return set
}

// findingsAreRelated checks if two findings reference the same vulnerability
// by checking if their ID/alias sets overlap
func findingsAreRelated(f1, f2 Finding) bool {
	set1 := createAliasSet(f1)
	set2 := createAliasSet(f2)

	// Check for any overlap
	for id := range set1 {
		if _, exists := set2[id]; exists {
			return true
		}
	}
	return false
}
