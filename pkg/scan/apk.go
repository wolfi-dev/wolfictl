package scan

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/adrg/xdg"
	"github.com/anchore/grype/grype"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
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
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
	sbomSyft "github.com/anchore/syft/syft/sbom"
	"github.com/chainguard-dev/clog"
	"github.com/charmbracelet/log"
	anchorelogger "github.com/wolfi-dev/wolfictl/pkg/anchorelog"
	"github.com/wolfi-dev/wolfictl/pkg/sbom"
)

const (
	mavenSearchBaseURL = "https://search.maven.org/solrsearch/select"
)

var DefaultGrypeDBDir = path.Join(xdg.CacheHome, "wolfictl", "grype", "db")

type Result struct {
	TargetAPK     TargetAPK
	Findings      []Finding
	GrypeDBStatus *v6.Status
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
	vulnProvider         vulnerability.Provider
	dbStatus             *v6.Status
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

	// Default to 24 hours if GRYPE_DB_MAX_ALLOWED_BUILT_AGE is unset
	maxAllowedBuiltAge := 24 * time.Hour

	grypeMaxAllowedBuiltAge := os.Getenv("GRYPE_DB_MAX_ALLOWED_BUILT_AGE")
	if grypeMaxAllowedBuiltAge != "" {
		parseMaxAllowedBuiltAge, err := time.ParseDuration(grypeMaxAllowedBuiltAge)
		if err != nil {
			return nil, fmt.Errorf("could not parse GRYPE_DB_MAX_ALLOWED_BUILT_AGE: %w", err)
		}
		maxAllowedBuiltAge = parseMaxAllowedBuiltAge
	}

	installCfg := installation.Config{
		DBRootDir:               dbDestDir,
		ValidateChecksum:        true,
		ValidateAge:             !opts.DisableDatabaseAgeValidation,
		MaxAllowedBuiltAge:      maxAllowedBuiltAge,
		UpdateCheckMaxFrequency: 1 * time.Hour,
	}

	distCfg := distribution.DefaultConfig()

	distClient, err := distribution.NewClient(distCfg)
	if err != nil {
		return nil, fmt.Errorf("creating distribution client: %w", err)
	}

	updateDB := true
	if dbArchivePath := opts.PathOfDatabaseArchiveToImport; dbArchivePath != "" {
		fmt.Fprintf(os.Stderr, "using local grype DB archive %q...\n", dbArchivePath)
		dbCurator, err := installation.NewCurator(installCfg, distClient)
		if err != nil {
			return nil, fmt.Errorf("unable to create the grype db import config: %w", err)
		}

		if err := dbCurator.Import(dbArchivePath); err != nil {
			return nil, fmt.Errorf("unable to import vulnerability database: %w", err)
		}

		updateDB = false
	}

	vulnProvider, dbStatus, err := grype.LoadVulnerabilityDB(distCfg, installCfg, updateDB)
	if err != nil {
		return nil, fmt.Errorf("failed to load vulnerability database: %w", err)
	}

	vulnerabilityMatcher := NewGrypeVulnerabilityMatcher(vulnProvider, opts.UseCPEs)

	return &Scanner{
		vulnProvider:         vulnProvider,
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

	grype.SetLogger(anchorelogger.NewSlogAdapter(logger.Base()))

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

		if allow, reason := shouldAllowMatch(m); !allow {
			log.Info(
				"match deemed invalid, dropping from results",
				"vulnerabilityID",
				m.Vulnerability.ID,
				"componentName",
				m.Package.Name,
				"componentVersion",
				m.Package.Version,
				"componentType",
				m.Package.Type,
				"reason",
				reason,
			)
			continue
		}

		finding, err := mapMatchToFinding(m, s.vulnProvider)
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

// shouldAllowMatch is a point where we can optionally filter out matches from
// the scan based on criteria we define. This function will return true unless
// it determines that the match should be dropped from the final result set. In
// this latter case, it also returns a string explanation of the reason for
// dropping the match.
func shouldAllowMatch(m match.Match) (allow bool, reason string) {
	// For now, since our new changes are centered on Go, allow all non-Go matches
	// to minimize unexpected disruption in scanning. We can widen the scope of this
	// filtering to other ecosystems when we're comfortable with it.
	if m.Package.Type != pkg.GoModulePkg {
		return true, ""
	}

	// Also exempt the Go stdlib.
	if m.Package.Name == "stdlib" {
		return true, ""
	}

	for _, d := range m.Details {
		if d.Type != match.CPEMatch {
			continue
		}

		// Be especially critical of CPE-based results...

		r, ok := d.Found.(match.CPEResult)
		if !ok {
			continue
		}

		p, ok := d.SearchedBy.(match.CPEParameters)
		if !ok {
			continue
		}

		// Drop matches where the version constraint is totally nonexistent, to reduce
		// false positives.
		if strings.HasPrefix(r.VersionConstraint, "none") {
			return false, "CPE has no version constraint"
		}

		// Drop matches where there's no fix.
		if m.Vulnerability.Fix.State != vulnerability.FixStateFixed {
			return false, "CPE-based match with no fix available"
		}

		// Older golang.org/x repositories have versions like "2019-03-20". This will
		// create false positives when versions are sorted, so let's drop these.
		if len(m.Vulnerability.Fix.Versions) != 1 {
			continue
		}

		// Only use CPEs from a trusted source.
		if !isMatchFromTrustedCPESource(p.CPEs, m.Package.CPEs) {
			return false, "CPE-based match from untrusted CPE source"
		}

		f := m.Vulnerability.Fix.Versions[0]
		if regexGolangDateVersion.MatchString(f) {
			return false, "CPE-based match unexpected version format ('XXXX-YY-ZZ')"
		}
	}

	return true, ""
}

func isMatchFromTrustedCPESource(searchCPEs []string, packageCPEs []cpe.CPE) bool {
	// Basically allow everything except "syft-generated".

	// First we'll build a lookup table of CPEs to sources, and then use that to
	// determine if the CPE(s) we matched on came from at least one trusted source.
	sourcesByCPE := make(map[string][]cpe.Source)
	for i := range packageCPEs {
		c := packageCPEs[i]
		cpeStr := c.Attributes.BindToFmtString()
		sourcesByCPE[cpeStr] = append(sourcesByCPE[cpeStr], c.Source)
	}

	for i := range searchCPEs {
		c := searchCPEs[i]
		srcs := sourcesByCPE[c]
		if len(srcs) == 0 {
			continue
		}
		for _, src := range srcs {
			if slices.Contains(trustedCPESources, src) {
				return true
			}
		}
	}

	return false
}

var trustedCPESources = []cpe.Source{
	sbom.CPESourceWolfictl,
	sbom.CPESourceMelangeConfiguration,
	cpe.NVDDictionaryLookupSource,
}

var regexGolangDateVersion = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// Close closes the scanner's database connection.
func (s *Scanner) Close() {
	if s.vulnProvider == nil {
		return
	}

	if err := s.vulnProvider.Close(); err != nil {
		clog.FromContext(context.Background()).Warnf("failed to close grype database: %v", err)
	}
}

func NewGrypeVulnerabilityMatcher(vulnProvider vulnerability.Provider, useCPEs bool) *grype.VulnerabilityMatcher {
	return &grype.VulnerabilityMatcher{
		VulnerabilityProvider: vulnProvider,
		Matchers:              createMatchers(useCPEs),
	}
}

func createMatchers(useCPEs bool) []match.Matcher {
	return matcher.NewDefaultMatchers(
		matcher.Config{
			Dotnet: dotnet.MatcherConfig{UseCPEs: useCPEs},
			Golang: golang.MatcherConfig{
				UseCPEs:                                true, // note: disregarding --use-cpes flag value
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
