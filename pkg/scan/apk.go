package scan

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"time"

	"github.com/adrg/xdg"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
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
	"github.com/anchore/syft/syft/pkg"
	sbomSyft "github.com/anchore/syft/syft/sbom"
	"github.com/chainguard-dev/clog"
	"github.com/wolfi-dev/wolfictl/pkg/sbom"
)

const (
	grypeDBListingURL  = "https://toolbox-data.anchore.io/grype/databases/listing.json"
	mavenSearchBaseURL = "https://search.maven.org/solrsearch/select"
)

var grypeDBDir = path.Join(xdg.CacheHome, "wolfictl", "grype", "db")

var grypeDBConfig = db.Config{
	DBRootDir:           grypeDBDir,
	ListingURL:          grypeDBListingURL,
	ValidateByHashOnGet: true,
	ValidateAge:         true,
	MaxAllowedBuiltAge:  24 * time.Hour,
}

type Result struct {
	TargetAPK     TargetAPK
	Findings      []Finding
	GrypeDBStatus *db.Status
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

	metadata, ok := p.Metadata.(pkg.ApkDBEntry)
	if !ok {
		return TargetAPK{}, fmt.Errorf("expected APK metadata, found %T", p.Metadata)
	}

	return TargetAPK{
		Name:              p.Name,
		Version:           p.Version,
		OriginPackageName: metadata.OriginPackage,
	}, nil
}

type Scanner struct {
	datastore            *store.Store
	dbStatus             *db.Status
	vulnerabilityMatcher *grype.VulnerabilityMatcher
}

// NewScanner initializes the grype DB for reuse across multiple scans.
func NewScanner(localDBFilePath string, useCPEs bool) (*Scanner, error) {
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

	datastore, dbStatus, dbCloser, err := grype.LoadVulnerabilityDB(grypeDBConfig, updateDB)
	if err != nil {
		return nil, fmt.Errorf("failed to load vulnerability database: %w", err)
	}
	defer dbCloser.Close()

	vulnerabilityMatcher := NewGrypeVulnerabilityMatcher(*datastore, useCPEs)

	return &Scanner{
		datastore:            datastore,
		dbStatus:             dbStatus,
		vulnerabilityMatcher: vulnerabilityMatcher,
	}, nil
}

// ScanAPK scans an APK file for vulnerabilities.
func (s *Scanner) ScanAPK(ctx context.Context, apk fs.File, distroID string) (*Result, error) {
	logger := clog.FromContext(ctx)

	stat, err := apk.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat APK file: %w", err)
	}

	logger.Info("scanning APK for vulnerabilities", "path", stat.Name())

	ssbom, err := sbom.CachedGenerate(ctx, stat.Name(), apk, distroID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SBOM from APK: %w", err)
	}

	return s.APKSBOM(ctx, ssbom)
}

// APKSBOM scans an SBOM of an APK for vulnerabilities.
func (s *Scanner) APKSBOM(ctx context.Context, ssbom *sbomSyft.SBOM) (*Result, error) {
	logger := clog.FromContext(ctx)

	logger.Debug("scanning APK SBOM for vulnerabilities", "packageCount", ssbom.Artifacts.Packages.PackageCount())

	apk, err := newTargetAPK(ssbom)
	if err != nil {
		return nil, err
	}

	syftPkgs := ssbom.Artifacts.Packages.Sorted()
	grypePkgs := grypePkg.FromPackages(syftPkgs, grypePkg.SynthesisConfig{GenerateMissingCPEs: false})

	logger.Debug("converted packages to grype packages", "packageCount", len(grypePkgs))

	// Find vulnerability matches
	matchesCollection, _, err := s.vulnerabilityMatcher.FindMatches(grypePkgs, grypePkg.Context{
		Source: &ssbom.Source,
		Distro: ssbom.Artifacts.LinuxDistribution,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerability matches: %w", err)
	}

	logger.Debug("grype matching finished", "matchCount", matchesCollection.Count())

	matches := matchesCollection.Sorted()

	var findings []Finding
	for i := range matches {
		m := matches[i]

		finding, err := mapMatchToFinding(m, s.datastore)
		if err != nil {
			return nil, fmt.Errorf("failed to map match to finding: %w", err)
		}
		if finding == nil {
			return nil, fmt.Errorf("failed to map match to finding: nil")
		}
		findings = append(findings, *finding)
	}

	result := &Result{
		TargetAPK:     apk,
		Findings:      findings,
		GrypeDBStatus: s.dbStatus,
	}

	return result, nil
}

func NewGrypeVulnerabilityMatcher(datastore store.Store, useCPEs bool) *grype.VulnerabilityMatcher {
	return &grype.VulnerabilityMatcher{
		Store:    datastore,
		Matchers: createMatchers(useCPEs),
	}
}

func createMatchers(useCPEs bool) []matcher.Matcher {
	return matcher.NewDefaultMatchers(
		matcher.Config{
			Dotnet: dotnet.MatcherConfig{UseCPEs: useCPEs},
			Golang: golang.MatcherConfig{
				UseCPEs:                                useCPEs,
				AlwaysUseCPEForStdlib:                  true,
				AllowMainModulePseudoVersionComparison: true,
			},
			Java: java.MatcherConfig{
				ExternalSearchConfig: java.ExternalSearchConfig{
					SearchMavenUpstream: true,
					MavenBaseURL:        mavenSearchBaseURL,
				},
				UseCPEs: useCPEs,
			},
			Javascript: javascript.MatcherConfig{UseCPEs: useCPEs},
			Python:     python.MatcherConfig{UseCPEs: useCPEs},
			Ruby:       ruby.MatcherConfig{UseCPEs: useCPEs},
			Rust:       rust.MatcherConfig{UseCPEs: useCPEs},
			Stock:      stock.MatcherConfig{UseCPEs: true},
		},
	)
}
