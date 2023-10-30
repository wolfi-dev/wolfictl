package scan

import (
	"fmt"
	"strings"

	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/store"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/file"
	"github.com/samber/lo"
)

// Finding represents a vulnerability finding for a single package.
type Finding struct {
	Package           Package
	Vulnerability     Vulnerability
	TriageAssessments []TriageAssessment
}

type Package struct {
	ID       string
	Name     string
	Version  string
	Type     string
	Location string
}

type Vulnerability struct {
	ID           string
	Severity     string
	Aliases      []string
	FixedVersion string
}

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

func mapMatchToFinding(m match.Match, datastore *store.Store) (*Finding, error) {
	metadata, err := datastore.MetadataProvider.GetMetadata(m.Vulnerability.ID, m.Vulnerability.Namespace)
	if err != nil {
		return nil, fmt.Errorf("unable to get metadata for vulnerability %s: %w", m.Vulnerability.ID, err)
	}

	var relatedMetadatas []*vulnerability.Metadata
	for _, relatedRef := range m.Vulnerability.RelatedVulnerabilities {
		relatedMetadata, err := datastore.MetadataProvider.GetMetadata(relatedRef.ID, relatedRef.Namespace)
		if err != nil {
			return nil, fmt.Errorf("unable to get metadata for related vulnerability %s: %w", relatedRef.ID, err)
		}
		if relatedMetadata == nil {
			continue
		}
		relatedMetadatas = append(relatedMetadatas, relatedMetadata)
	}

	aliases := lo.Map(relatedMetadatas, func(m *vulnerability.Metadata, _ int) string {
		return m.ID
	})

	locations := lo.Map(m.Package.Locations.ToSlice(), func(l file.Location, _ int) string {
		return "/" + l.RealPath
	})

	f := &Finding{
		Package: Package{
			ID:       string(m.Package.ID),
			Name:     m.Package.Name,
			Version:  m.Package.Version,
			Type:     string(m.Package.Type),
			Location: strings.Join(locations, ", "),
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
	if vuln.Fix.State != v5.FixedState {
		return ""
	}

	return strings.Join(vuln.Fix.Versions, ", ")
}
