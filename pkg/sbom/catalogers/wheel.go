package catalogers

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

type Wheel struct{}

func (w Wheel) Name() string {
	return "wheel-cataloger"
}

func (w Wheel) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	locations, err := resolver.FilesByGlob("**/*.whl")
	if err != nil {
		return nil, nil, fmt.Errorf("finding wheel files: %w", err)
	}

	var pkgs []pkg.Package
	for _, l := range locations {
		wheelFile, err := resolver.FileContentsByLocation(l)
		if err != nil {
			return nil, nil, fmt.Errorf("getting file contents: %w", err)
		}

		metadata, err := extractWheelMetadata(wheelFile)
		if err != nil {
			return nil, nil, fmt.Errorf("extracting wheel metadata: %w", err)
		}

		licenses := pkg.NewLicenseSet()
		if license, ok := metadata["License"]; ok {
			licenses.Add(pkg.NewLicense(license))
		}

		p := pkg.Package{
			Name:      metadata["Name"],
			Version:   metadata["Version"],
			FoundBy:   w.Name(),
			Locations: file.NewLocationSet(l),
			Licenses:  licenses,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			PURL:      createPURLForWheel(metadata),
		}

		pkgs = append(pkgs, p)
	}

	return pkgs, nil, nil
}

func extractWheelMetadata(wheelFile io.Reader) (map[string]string, error) {
	b, err := io.ReadAll(wheelFile)
	if err != nil {
		return nil, fmt.Errorf("reading wheel file to a buffer: %w", err)
	}
	buf := bytes.NewReader(b)
	zipReader, err := zip.NewReader(buf, buf.Size())
	if err != nil {
		return nil, fmt.Errorf("reading zip file: %w", err)
	}

	metadata := make(map[string]string)

	for _, file := range zipReader.File {
		if strings.HasSuffix(file.Name, ".dist-info/METADATA") {
			rc, err := file.Open()
			if err != nil {
				return nil, fmt.Errorf("opening METADATA file: %w", err)
			}
			defer rc.Close()

			scanner := bufio.NewScanner(rc)
			for scanner.Scan() {
				line := scanner.Text()
				if line == "" {
					continue
				}
				parts := strings.SplitN(line, ": ", 2)
				if len(parts) == 2 {
					key, value := parts[0], parts[1]
					metadata[key] = value
				}
			}
			if err := scanner.Err(); err != nil {
				return nil, fmt.Errorf("scanning METADATA file: %w", err)
			}
		}
	}

	return metadata, nil
}

func createPURLForWheel(metadata map[string]string) string {
	// Construct the Package URL (PURL) based on the metadata
	name := metadata["Name"]
	version := metadata["Version"]
	return fmt.Sprintf("pkg:pypi/%s@%s", name, version)
}

var WheelReference = pkgcataloging.CatalogerReference{
	Cataloger:     Wheel{},
	AlwaysEnabled: true,
}
