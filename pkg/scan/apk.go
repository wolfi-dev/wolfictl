package scan

import (
	"fmt"
	"io"
	"os"
	"path"
	"time"

	"github.com/adrg/xdg"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/match"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/store"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/source"
	"github.com/samber/lo"
	"github.com/wolfi-dev/wolfictl/pkg/tar"
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

var syftCatalogersEnabled = []string{
	"apkdb",
	"binary",
	"dotnet-deps",
	"go-module-binary",
	"graalvm-native-image",
	"java",
	"javascript-package",
	"php-composer-installed",
	"portage",
	"python-package",
	"r-package-cataloger",
	"ruby-gemspec",
}

// APK scans an APK file for vulnerabilities.
func APK(file io.Reader) ([]*Finding, error) {
	// Create a temp directory to house the unpacked APK file
	tempDir, err := os.MkdirTemp("", "wolfictl-scan-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Unpack apk to temp directory
	err = tar.Untar(file, tempDir)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack apk file: %w", err)
	}

	// TODO: use a managed cache of APK SBOMs (Syft format)

	src, err := source.NewFromDirectory(
		source.DirectoryConfig{
			Path: tempDir,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create source from directory: %w", err)
	}

	cfg := cataloger.DefaultConfig()
	cfg.Catalogers = syftCatalogersEnabled

	packageCollection, _, distro, err := syft.CatalogPackages(src, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to catalog packages: %w", err)
	}

	syftPkgs := packageCollection.Sorted()

	store, _, dbCloser, err := grype.LoadVulnerabilityDB(grypeDBConfig, true)
	if err != nil {
		return nil, fmt.Errorf("failed to load vulnerability database: %w", err)
	}
	defer dbCloser.Close()

	matcher := grype.DefaultVulnerabilityMatcher(*store)
	sourceDescription := src.Describe()
	grypePkgs := grypePkg.FromPackages(syftPkgs, grypePkg.SynthesisConfig{GenerateMissingCPEs: false})
	matchesCollection, _, err := matcher.FindMatches(grypePkgs, grypePkg.Context{
		Source: &sourceDescription,
		Distro: distro,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerability matches: %w", err)
	}

	matches := matchesCollection.Sorted()

	var findings []*Finding
	for _, m := range matches {
		finding, err := mapMatchToFinding(m, store)
		if err != nil {
			return nil, fmt.Errorf("failed to map match to finding: %w", err)
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// Finding represents a vulnerability finding for a single package.
type Finding struct {
	Package         string
	Version         string
	Type            string
	VulnerabilityID string
	Severity        string
	Aliases         []string
}

func mapMatchToFinding(m match.Match, store *store.Store) (*Finding, error) {
	metadata, err := store.MetadataProvider.GetMetadata(m.Vulnerability.ID, m.Vulnerability.Namespace)
	if err != nil {
		return nil, fmt.Errorf("unable to get metadata for vulnerability %s: %w", m.Vulnerability.ID, err)
	}

	var relatedMetadatas []*vulnerability.Metadata
	for _, relatedRef := range m.Vulnerability.RelatedVulnerabilities {
		relatedMetadata, err := store.MetadataProvider.GetMetadata(relatedRef.ID, relatedRef.Namespace)
		if err != nil {
			return nil, fmt.Errorf("unable to get metadata for related vulnerability %s: %w", relatedRef.ID, err)
		}
		relatedMetadatas = append(relatedMetadatas, relatedMetadata)
	}

	aliases := lo.Map(relatedMetadatas, func(m *vulnerability.Metadata, _ int) string {
		return m.ID
	})

	f := &Finding{
		Package:         m.Package.Name,
		Version:         m.Package.Version,
		Type:            string(m.Package.Type),
		VulnerabilityID: m.Vulnerability.ID,
		Severity:        metadata.Severity,
		Aliases:         aliases,
	}

	return f, nil
}
