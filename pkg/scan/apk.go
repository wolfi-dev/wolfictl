package scan

import (
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/adrg/xdg"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/match"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/store"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/formats/syftjson"
	sbomSyft "github.com/anchore/syft/syft/sbom"
	"github.com/samber/lo"
	"github.com/wolfi-dev/wolfictl/pkg/sbom"
)

const grypeDBListingURL = "https://toolbox-data.anchore.io/grype/databases/listing.json"

var grypeDBDir = path.Join(xdg.CacheHome, "wolfictl", "grype", "db")

var grypeDBConfig = db.Config{
	DBRootDir:           grypeDBDir,
	ListingURL:          grypeDBListingURL,
	ValidateByHashOnGet: true,
	ValidateAge:         true,
	MaxAllowedBuiltAge:  24 * time.Hour,
}

// APK scans an APK file for vulnerabilities.
func APK(f io.Reader, localDBFilePath string) ([]*Finding, error) {
	s, err := sbom.Generate(f, "wolfi") // TODO: make this configurable
	if err != nil {
		return nil, fmt.Errorf("failed to generate SBOM: %w", err)
	}

	return scan(s, localDBFilePath)
}

// APKSBOM scans an SBOM of an APK for vulnerabilities.
func APKSBOM(r io.Reader, localDBFilePath string) ([]*Finding, error) {
	s, err := syftjson.Format().Decode(r)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Syft SBOM: %w", err)
	}

	return scan(s, localDBFilePath)
}

func scan(s *sbomSyft.SBOM, localDBFilePath string) ([]*Finding, error) {
	updateDB := true
	if localDBFilePath != "" {
		fmt.Fprintf(os.Stderr, "Loading local grype DB %s...\n", localDBFilePath)
		dbCurator, err := db.NewCurator(grypeDBConfig)
		if err != nil {
			return nil, fmt.Errorf("unable to create the grype db import config: %w", err)
		}

		if err := dbCurator.ImportFrom(localDBFilePath); err != nil {
			return nil, fmt.Errorf("unable to import vulnerability database: %w", err)
		}

		updateDB = false
	}

	datastore, _, dbCloser, err := grype.LoadVulnerabilityDB(grypeDBConfig, updateDB)
	if err != nil {
		return nil, fmt.Errorf("failed to load vulnerability database: %w", err)
	}
	defer dbCloser.Close()

	matcher := grype.DefaultVulnerabilityMatcher(*datastore)

	syftPkgs := s.Artifacts.Packages.Sorted()
	grypePkgs := grypePkg.FromPackages(syftPkgs, grypePkg.SynthesisConfig{GenerateMissingCPEs: false})

	// Find vulnerability matches
	matchesCollection, _, err := matcher.FindMatches(grypePkgs, grypePkg.Context{
		Source: &s.Source,
		Distro: s.Artifacts.LinuxDistribution,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerability matches: %w", err)
	}

	matches := matchesCollection.Sorted()

	var findings []*Finding
	for i := range matches {
		m := matches[i]

		finding, err := mapMatchToFinding(m, datastore)
		if err != nil {
			return nil, fmt.Errorf("failed to map match to finding: %w", err)
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// Finding represents a vulnerability finding for a single package.
type Finding struct {
	Package       Package
	Vulnerability Vulnerability
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
