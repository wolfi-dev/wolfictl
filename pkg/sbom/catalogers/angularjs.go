package catalogers

import (
	"context"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

const JSFilePkg = "js-file"

var (
	angularCopyrightNotice = regexp.MustCompile(`/\*
 AngularJS (v\d+(\.\d+)*)
 \(c\) .*
 License: MIT
\*/`)
)

// AngularJS is a cataloger for AngularJS (https://angularjs.org/) and its
// related packages found in standalone minified JS files.
type AngularJS struct{}

func (a AngularJS) Name() string {
	return "angularjs-cataloger"
}

func (a AngularJS) Catalog(_ context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	locations, err := resolver.FilesByGlob("**/angular*.min.js")
	if err != nil {
		return nil, nil, fmt.Errorf("finding minified js files: %w", err)
	}

	var pkgs []pkg.Package
	for _, l := range locations {
		filename := path.Base(l.Path())
		packageName := strings.TrimSuffix(filename, ".min.js")

		rc, err := resolver.FileContentsByLocation(l)
		if err != nil {
			return nil, nil, fmt.Errorf("getting file contents: %w", err)
		}

		buf, err := io.ReadAll(rc)
		if err != nil {
			return nil, nil, fmt.Errorf("reading file contents: %w", err)
		}
		rc.Close()

		matches := angularCopyrightNotice.FindStringSubmatch(string(buf))
		if len(matches) < 2 {
			continue
		}

		version := matches[1]

		trimmedVersion := strings.TrimPrefix(version, "v")
		cpeValue, err := cpe.New(fmt.Sprintf("cpe:2.3:a:angularjs:%s:%s:*:*:*:*:node.js:*:*", packageName, trimmedVersion), cpe.Source("wolfictl"))
		if err != nil {
			return nil, nil, fmt.Errorf("creating CPE: %w", err)
		}

		p := a.newPackageFromJSFile(packageName, version, "MIT", l, cpeValue)
		pkgs = append(pkgs, p)
	}

	return pkgs, nil, nil
}

var AngularJSReference = pkgcataloging.CatalogerReference{
	Cataloger:     AngularJS{},
	AlwaysEnabled: true,
}

func (a AngularJS) newPackageFromJSFile(name, version, license string, l file.Location, cpeValue cpe.CPE) pkg.Package {
	return pkg.Package{
		Name:      name,
		Version:   version,
		FoundBy:   a.Name(),
		Locations: file.NewLocationSet(l),
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense(license)),
		Language:  pkg.JavaScript,
		Type:      JSFilePkg,
		CPEs:      []cpe.CPE{cpeValue},
		PURL:      "", // TODO: Figure out a suitable value.
	}
}
