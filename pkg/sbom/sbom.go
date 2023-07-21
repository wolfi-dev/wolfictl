package sbom

import (
	"fmt"
	"io"
	"os"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/wolfi-dev/wolfictl/pkg/tar"
)

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

// Generate creates an SBOM for the given APK file.
func Generate(f io.Reader, distroID string) (*sbom.SBOM, error) {
	// Create a temp directory to house the unpacked APK file
	tempDir, err := os.MkdirTemp("", "wolfictl-sbom-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Unpack apk to temp directory
	err = tar.Untar(f, tempDir)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack apk file: %w", err)
	}

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

	packageCollection, _, _, err := syft.CatalogPackages(src, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to catalog packages: %w", err)
	}

	s := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: packageCollection,
			LinuxDistribution: &linux.Release{
				ID: distroID,
			},
		},
		Source: src.Describe(),
		Descriptor: sbom.Descriptor{
			Name: "wolfictl",
		},
	}

	return &s, nil
}
