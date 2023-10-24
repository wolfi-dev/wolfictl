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
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/matcher/dotnet"
	"github.com/anchore/grype/grype/matcher/golang"
	"github.com/anchore/grype/grype/matcher/java"
	"github.com/anchore/grype/grype/matcher/javascript"
	"github.com/anchore/grype/grype/matcher/python"
	"github.com/anchore/grype/grype/matcher/ruby"
	"github.com/anchore/grype/grype/matcher/rust"
	"github.com/anchore/grype/grype/matcher/stock"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/store"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
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

type Result struct {
	TargetAPK TargetAPK
	Findings  []*Finding
}

type TargetAPK struct {
	Name              string
	Version           string
	OriginPackageName string
}

// Origin returns the name of the origin package, if the package's metadata
// indicates an origin package. Otherwise, it returns the package name.
func (t TargetAPK) Origin() string {
	if t.OriginPackageName != "" {
		return t.OriginPackageName
	}

	return t.Name
}

func newTargetAPK(s *sbomSyft.SBOM) (TargetAPK, error) {
	// There should be exactly one APK package in the SBOM, and it should be the APK
	// we intended to scan.

	pkgs := s.Artifacts.Packages.Sorted(pkg.ApkPkg)
	if len(pkgs) != 1 {
		return TargetAPK{}, fmt.Errorf("expected exactly one APK package, found %d", len(pkgs))
	}

	p := pkgs[0]

	metadata, ok := p.Metadata.(pkg.ApkMetadata)
	if !ok {
		return TargetAPK{}, fmt.Errorf("expected APK metadata, found %T", p.Metadata)
	}

	return TargetAPK{
		Name:              p.Name,
		Version:           p.Version,
		OriginPackageName: metadata.OriginPackage,
	}, nil
}

// APKSBOM scans an SBOM of an APK for vulnerabilities.
func APKSBOM(r io.Reader, localDBFilePath string) (*Result, error) {
	s, err := sbom.FromSyftJSON(r)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Syft SBOM: %w", err)
	}

	return scan(s, localDBFilePath)
}

func scan(s *sbomSyft.SBOM, localDBFilePath string) (*Result, error) {
	apk, err := newTargetAPK(s)
	if err != nil {
		return nil, err
	}

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

	vulnerabilityMatcher := newGrypeVulnerabilityMatcher(*datastore)

	syftPkgs := s.Artifacts.Packages.Sorted()
	grypePkgs := grypePkg.FromPackages(syftPkgs, grypePkg.SynthesisConfig{GenerateMissingCPEs: false})

	// Find vulnerability matches
	matchesCollection, _, err := vulnerabilityMatcher.FindMatches(grypePkgs, grypePkg.Context{
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

	result := &Result{
		TargetAPK: apk,
		Findings:  findings,
	}

	return result, nil
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

func newGrypeVulnerabilityMatcher(datastore store.Store) *grype.VulnerabilityMatcher {
	return &grype.VulnerabilityMatcher{
		Store:    datastore,
		Matchers: createMatchers(),
	}
}

func createMatchers() []matcher.Matcher {
	return matcher.NewDefaultMatchers(
		matcher.Config{
			Dotnet:     dotnet.MatcherConfig{UseCPEs: false},
			Golang:     golang.MatcherConfig{UseCPEs: false, AlwaysUseCPEForStdlib: true},
			Java:       java.MatcherConfig{UseCPEs: false},
			Javascript: javascript.MatcherConfig{UseCPEs: false},
			Python:     python.MatcherConfig{UseCPEs: false},
			Ruby:       ruby.MatcherConfig{UseCPEs: false},
			Rust:       rust.MatcherConfig{UseCPEs: false},
			Stock:      stock.MatcherConfig{UseCPEs: true},
		},
	)
}
