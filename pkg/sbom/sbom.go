package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/formats/syftjson"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger"
	cpegen "github.com/anchore/syft/syft/pkg/cataloger/common/cpe"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/package-url/packageurl-go"
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
func Generate(inputFilePath string, f io.Reader, distroID string) (*sbom.SBOM, error) {
	// Create a temp directory to house the unpacked APK file
	// if TMPDIR environment variable is not set, uses the default directory for temporary files
	tempDirPath := os.Getenv("TMPDIR")
	tempDir, err := os.MkdirTemp(tempDirPath, "wolfictl-sbom-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Unpack apk to temp directory
	err = tar.Untar(f, tempDir)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack apk file: %w", err)
	}

	// Analyze the APK metadata
	pkginfo, err := os.Open(path.Join(tempDir, pkginfoPath))
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", pkginfoPath, err)
	}
	defer pkginfo.Close()
	apkPackage, err := newAPKPackage(pkginfo, distroID)
	if err != nil {
		return nil, fmt.Errorf("failed to create APK package: %w", err)
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

	packageCollection.Add(*apkPackage)

	s := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: packageCollection,
			LinuxDistribution: &linux.Release{
				ID: distroID,
			},
		},
		Source: getDeterministicSourceDescription(src, inputFilePath),
		Descriptor: sbom.Descriptor{
			Name: "wolfictl",
		},
	}

	return &s, nil
}

func getDeterministicSourceDescription(src *source.DirectorySource, inputFilePath string) source.Description {
	description := src.Describe()

	description.ID = "(redacted for determinism)"
	description.Name = inputFilePath
	metadata := source.DirectorySourceMetadata{
		Path: inputFilePath,
	}
	description.Metadata = metadata

	return description
}

func newAPKPackage(r io.Reader, distroID string) (*pkg.Package, error) {
	pkginfo, err := parsePkgInfo(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse APK metadata: %w", err)
	}

	metadata := pkg.ApkMetadata{
		Package:       pkginfo.PkgName,
		OriginPackage: pkginfo.Origin,
		Version:       pkginfo.PkgVer,
		Architecture:  pkginfo.Arch,
		URL:           pkginfo.URL,
		Description:   pkginfo.PkgDesc,
		Size:          int(pkginfo.Size),
		Dependencies:  pkginfo.Depends,
		Provides:      pkginfo.Provides,
		Checksum:      pkginfo.DataHash,
		GitCommit:     pkginfo.Commit,
	}

	p := pkg.Package{
		Name:         pkginfo.PkgName,
		Version:      pkginfo.PkgVer,
		FoundBy:      "wolfictl",
		Locations:    file.NewLocationSet(file.NewLocation(pkginfoPath)),
		Licenses:     pkg.NewLicenseSet(pkg.NewLicense(pkginfo.License)),
		Type:         pkg.ApkPkg,
		MetadataType: pkg.ApkMetadataType,
		Metadata:     metadata,
	}

	p.PURL = generatePURL(*pkginfo, distroID)
	p.CPEs = generateCPEs(p)

	p.SetID()

	return &p, nil
}

func generatePURL(info pkgInfo, distroID string) string {
	purlQualifiers := []packageurl.Qualifier{
		{Key: pkg.PURLQualifierArch, Value: info.Arch},
	}
	if info.Origin != "" {
		purlQualifiers = append(purlQualifiers, packageurl.Qualifier{Key: "origin", Value: info.Origin})
	}

	return packageurl.NewPackageURL(packageurl.TypeApk, distroID, info.PkgName, info.PkgVer, purlQualifiers, "").String()
}

func generateCPEs(p pkg.Package) []cpe.CPE {
	dictionaryCPE, ok := cpegen.DictionaryFind(p)
	if ok {
		return []cpe.CPE{dictionaryCPE}
	}

	return cpegen.Generate(p)
}

// ToSyftJSON returns the SBOM as a reader of the Syft JSON format.
func ToSyftJSON(s *sbom.SBOM) (io.Reader, error) {
	buf := new(bytes.Buffer)

	model := syftjson.ToFormatModel(*s)
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(model)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SBOM: %w", err)
	}

	return buf, nil
}

// FromSyftJSON returns an SBOM from a reader of the Syft JSON format.
func FromSyftJSON(r io.Reader) (*sbom.SBOM, error) {
	s, err := syftjson.Format().Decode(r)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Syft JSON: %w", err)
	}

	return s, nil
}
