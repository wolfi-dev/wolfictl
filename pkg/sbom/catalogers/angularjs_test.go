package catalogers

import (
	"context"
	"testing"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
)

func TestAngularJS_Catalog(t *testing.T) {
	c := AngularJS{}

	resolver := file.NewMockResolverForPaths(
		"testdata/angular.min.js",
		"testdata/angular-resource.min.js",
	)

	packages, relationships, err := c.Catalog(context.Background(), resolver)
	if err != nil {
		t.Fatalf("Catalog returned an error: %+v", err)
	}

	if len(relationships) != 0 {
		t.Errorf("didn't expect any relationships to be found: %+v", relationships)
	}

	expectedPackages := []pkg.Package{
		{
			Name:      "angular",
			Version:   "v1.8.0",
			Type:      JSFilePkg,
			FoundBy:   "angularjs-cataloger",
			Locations: file.NewLocationSet(file.NewLocation("testdata/angular.min.js")),
			Licenses:  pkg.NewLicenseSet(pkg.NewLicense("MIT")),
			Language:  pkg.JavaScript,
			CPEs: []cpe.CPE{{
				Attributes: cpe.Attributes{
					Part:     "a",
					Vendor:   "angularjs",
					Product:  "angular",
					Version:  "1.8.0",
					TargetSW: "node.js",
				},
				Source: "wolfictl",
			}},
		},
		{
			Name:      "angular-resource",
			Version:   "v1.8.0",
			FoundBy:   "angularjs-cataloger",
			Locations: file.NewLocationSet(file.NewLocation("testdata/angular-resource.min.js")),
			Licenses:  pkg.NewLicenseSet(pkg.NewLicense("MIT")),
			Language:  pkg.JavaScript,
			Type:      JSFilePkg,
			CPEs: []cpe.CPE{{
				Attributes: cpe.Attributes{
					Part:     "a",
					Vendor:   "angularjs",
					Product:  "angular-resource",
					Version:  "1.8.0",
					TargetSW: "node.js",
				},
				Source: "wolfictl",
			}},
		},
	}

	assert.Equalf(t, len(expectedPackages), len(packages), "unexpected number of packages found: %d", len(packages))

	assert.Equal(t, expectedPackages, packages)
}
