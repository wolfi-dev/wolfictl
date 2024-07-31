package catalogers

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/chainguard-dev/clog"
)

// https://pip.pypa.io/en/stable/development/vendoring-policy/
type PipVendor struct{}

func (a PipVendor) Name() string {
	return "pip-vendor-cataloger"
}

func (a PipVendor) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	log := clog.FromContext(ctx)

	// e.g. usr/lib/python3.12/site-packages/pip/_vendor/vendor.txt
	locations, err := resolver.FilesByGlob("**/pip/_vendor/vendor.txt")
	if err != nil {
		return nil, nil, fmt.Errorf("finding vendored pip files: %w", err)
	}

	var pkgs []pkg.Package
	for _, l := range locations {
		rc, err := resolver.FileContentsByLocation(l)
		if err != nil {
			return nil, nil, fmt.Errorf("getting file contents: %w", err)
		}

		buf, err := io.ReadAll(rc)
		if err != nil {
			return nil, nil, fmt.Errorf("reading file contents: %w", err)
		}
		rc.Close()

		pkgVersions, err := parsePipVendorFile(buf)
		if err != nil {
			log.Warnf("parsing vendor.txt file %q: %v", l.Path(), err)
			continue
		}

		for p, ver := range pkgVersions {
			pkgs = append(pkgs, pkg.Package{
				Name:      p,
				Version:   ver,
				FoundBy:   a.Name(),
				Locations: file.NewLocationSet(l),
				Language:  pkg.Python,
				Type:      pkg.PythonPkg,
			})
		}
	}

	return pkgs, nil, nil
}

func parsePipVendorFile(buf []byte) (map[string]string, error) {
	packages := make(map[string]string)
	lines := strings.Split(string(buf), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "==")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid line: %q", line)
		}
		packages[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return packages, nil
}

var PipVendorReference = pkgcataloging.CatalogerReference{
	Cataloger:     PipVendor{},
	AlwaysEnabled: true,
}
