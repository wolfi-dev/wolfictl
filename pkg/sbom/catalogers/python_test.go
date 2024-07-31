package catalogers

import (
	"context"
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func TestPipVendor(t *testing.T) {
	want := map[string]string{
		"CacheControl":      "0.14.0",
		"distlib":           "0.3.8",
		"distro":            "1.9.0",
		"msgpack":           "1.0.8",
		"packaging":         "24.1",
		"platformdirs":      "4.2.1",
		"pyproject-hooks":   "1.0.0",
		"requests":          "2.32.3",
		"certifi":           "2024.2.2",
		"idna":              "3.7",
		"urllib3":           "1.26.18",
		"rich":              "13.7.1",
		"pygments":          "2.17.2",
		"typing_extensions": "4.11.0",
		"resolvelib":        "1.0.1",
		"setuptools":        "69.5.1",
		"tenacity":          "8.2.3",
		"tomli":             "2.0.1",
		"truststore":        "0.9.1",
	}
	pkgs, _, err := PipVendor{}.Catalog(context.Background(), file.NewMockResolverForPaths(
		"testdata/pip/_vendor/vendor.txt",
		"testdata/bad/pip/_vendor/vendor.txt",
	))
	if err != nil {
		t.Fatalf("failed to catalog: %+v", err)
	}

	if len(pkgs) != len(want) {
		t.Fatalf("unexpected package count: %d", len(pkgs))
	}

	got := map[string]string{}

	for _, p := range pkgs {
		got[p.Name] = p.Version
		if p.Name == "" {
			t.Errorf("missing package name")
		}
		if p.Version == "" {
			t.Errorf("missing package version")
		}
		if p.Type != pkg.PythonPkg {
			t.Errorf("unexpected package type: %s", p.Type)
		}
		if p.Language != pkg.Python {
			t.Errorf("unexpected package language: %s", p.Language)
		}
	}

	for k, v := range want {
		if got[k] != v {
			t.Errorf("missing package: %s==%s", k, v)
		}
	}
	for k, v := range got {
		if want[k] != v {
			t.Errorf("extra package: %s==%s", k, v)
		}
	}
}
