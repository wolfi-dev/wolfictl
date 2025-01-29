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
	db "github.com/anchore/grype/grype/db/legacy/distribution"
	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/db/v5/matcher"
	"github.com/anchore/grype/grype/db/v5/matcher/dotnet"
	"github.com/anchore/grype/grype/db/v5/matcher/golang"
	"github.com/anchore/grype/grype/db/v5/matcher/java"
	"github.com/anchore/grype/grype/db/v5/matcher/javascript"
	"github.com/anchore/grype/grype/db/v5/matcher/python"
	"github.com/anchore/grype/grype/db/v5/matcher/ruby"
	"github.com/anchore/grype/grype/db/v5/matcher/rust"
	"github.com/anchore/grype/grype/db/v5/matcher/stock"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/syft/syft/pkg"
	sbomSyft "github.com/anchore/syft/syft/sbom"
	"github.com/chainguard-dev/clog"
	"github.com/wolfi-dev/wolfictl/pkg/sbom"
)

const (
	grypeDBListingURL  = "https://toolbox-data.anchore.io/grype/databases/listing.json"
	mavenSearchBaseURL = "https://search.maven.org/solrsearch/select"
)

var DefaultGrypeDBDir = path.Join(xdg.CacheHome, "wolfictl", "grype", "db")

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
	datastore            *v5.ProviderStore
	dbStatus             *db.Status
	vulnerabilityMatcher *grype.VulnerabilityMatcher
	disableSBOMCache     bool
}

// Options determine the configuration for a new Scanner. The zero-value of this
// struct is a valid configuration.
type Options struct {
	// PathOfDatabaseArchiveToImport, if set, is the path to a Grype vulnerability
	// database archive (.tar.gz file) from which a database will be loaded by
	// Grype.
	//
	// If empty, the default Grype database loading behavior will be used (e.g.
	// downloading the database from the Internet).
	PathOfDatabaseArchiveToImport string

	// PathOfDatabaseDestinationDirectory is the directory to which the Grype
	// database will be extracted, and where the database will be loaded from at
	// runtime. If empty, the value of DefaultGrypeDBDir will be used.
	PathOfDatabaseDestinationDirectory string

	// UseCPEs controls whether the scanner will use CPEs to match vulnerabilities
	// for matcher types that default to not using CPE matching. Most consumers will
	// probably want this set to false in order to avoid excessive noise from
	// matching.
	UseCPEs bool

	// DisableDatabaseAgeValidation controls whether the scanner will validate the
	// age of the vulnerability database before using it. If true, the scanner will
	// not validate the age of the database. This bool should always be set to false
	// except for testing purposes.
	DisableDatabaseAgeValidation bool

	// DisableSBOMCache controls whether the scanner will cache SBOMs generated from
	// APKs. If true, the scanner will not cache SBOMs or use existing cached SBOMs.
	DisableSBOMCache bool
}

// DefaultOptions is the recommended default configuration for a new Scanner.
// These options are suitable for most use scanning cases.
var DefaultOptions = Options{}

// NewScanner initializes the grype DB for reuse across multiple scans.
func NewScanner(opts Options) (*Scanner, error) {
	dbDestDir := opts.PathOfDatabaseDestinationDirectory
	if dbDestDir == "" {
		dbDestDir = DefaultGrypeDBDir
	}

	grypeDBConfig := db.Config{
		DBRootDir:           dbDestDir,
		ListingURL:          grypeDBListingURL,
		ValidateByHashOnGet: true,
		ValidateAge:         !opts.DisableDatabaseAgeValidation,
		MaxAllowedBuiltAge:  24 * time.Hour,
	}

	updateDB := true
	if dbArchivePath := opts.PathOfDatabaseArchiveToImport; dbArchivePath != "" {
		fmt.Fprintf(os.Stderr, "using local grype DB archive %q...\n", dbArchivePath)
		dbCurator, err := db.NewCurator(grypeDBConfig)
		if err != nil {
			return nil, fmt.Errorf("unable to create the grype db import config: %w", err)
		}

		if err := dbCurator.ImportFrom(dbArchivePath); err != nil {
			return nil, fmt.Errorf("unable to import vulnerability database: %w", err)
		}

		updateDB = false
	}

	datastore, dbStatus, err := grype.LoadVulnerabilityDB(grypeDBConfig, updateDB)
	if err != nil {
		return nil, fmt.Errorf("failed to load vulnerability database: %w", err)
	}

	vulnerabilityMatcher := NewGrypeVulnerabilityMatcher(*datastore, opts.UseCPEs)

	return &Scanner{
		datastore:            datastore,
		dbStatus:             dbStatus,
		vulnerabilityMatcher: vulnerabilityMatcher,
		disableSBOMCache:     opts.DisableSBOMCache,
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

	var ssbom *sbomSyft.SBOM

	if s.disableSBOMCache {
		ssbom, err = sbom.Generate(ctx, stat.Name(), apk, distroID)
	} else {
		ssbom, err = sbom.CachedGenerate(ctx, stat.Name(), apk, distroID)
	}

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

	logger.Info("converted packages to grype packages", "packageCount", len(grypePkgs))

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

// Close closes the scanner's database connection.
func (s *Scanner) Close() {
	if s.datastore == nil {
		return
	}

	if err := s.datastore.Close(); err != nil {
		clog.FromContext(context.Background()).Warnf("failed to close grype database: %v", err)
	}
}

func NewGrypeVulnerabilityMatcher(datastore v5.ProviderStore, useCPEs bool) *grype.VulnerabilityMatcher {
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
				AllowMainModulePseudoVersionComparison: false,
			},
			Java: java.MatcherConfig{
				ExternalSearchConfig: java.ExternalSearchConfig{
					SearchMavenUpstream: true,
					MavenBaseURL:        mavenSearchBaseURL,
					MavenRateLimit:      400 * time.Millisecond, // increased from the default of 300ms to avoid rate limiting with extremely large set of java packages such as druid
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
