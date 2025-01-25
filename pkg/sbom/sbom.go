package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/format/syftjson/model"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	cpegen "github.com/anchore/syft/syft/pkg/cataloger/common/cpe"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/chainguard-dev/clog"
	"github.com/package-url/packageurl-go"
	"github.com/wolfi-dev/wolfictl/pkg/sbom/catalogers"
	"github.com/wolfi-dev/wolfictl/pkg/tar"
)

const cpeSourceWolfictl cpe.Source = "wolfictl"

// Generate creates an SBOM for the given APK file.
func Generate(ctx context.Context, inputFilePath string, f io.Reader, distroID string) (*sbom.SBOM, error) {
	logger := clog.FromContext(ctx)

	logger.Info("generating SBOM for APK file", "path", inputFilePath, "distroID", distroID)

	// Create a temp directory to house the unpacked APK file
	tempDir, err := os.MkdirTemp("", "wolfictl-sbom-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer func() {
		logger.Debug("cleaning up temp directory", "path", tempDir)
		_ = os.RemoveAll(tempDir)
	}()

	logger.Debug("created temp directory to unpack APK", "path", tempDir)

	// Unpack apk to temp directory
	if err := tar.Untar(f, tempDir); err != nil {
		return nil, fmt.Errorf("failed to unpack apk file: %w", err)
	}
	logger.Debug("unpacked APK file to temp directory", "apkFilePath", inputFilePath)

	// Sanity check: count the number of files in the temp directory. Create an
	// fs.FS and walk it. We'll also use this to attach a list of files to the APK
	// package.

	var includedFiles []string

	tempFsys := os.DirFS(tempDir)
	err = fs.WalkDir(tempFsys, ".", func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		logger.Debug("apk temp directory item", "path", path)
		includedFiles = append(includedFiles, path)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking APK's temp directory: %w", err)
	}

	// Analyze the APK metadata
	pkginfo, err := os.Open(path.Join(tempDir, pkginfoPath))
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", pkginfoPath, err)
	}
	defer pkginfo.Close()
	apkPackage, err := newAPKPackage(pkginfo, distroID, includedFiles)
	if err != nil {
		return nil, fmt.Errorf("failed to create APK package: %w", err)
	}
	logger.Debug("synthesized APK package for SBOM", "name", apkPackage.Name, "version", apkPackage.Version, "id", string(apkPackage.ID()))

	src, err := directorysource.New(
		directorysource.Config{
			Path: tempDir,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create source from directory: %w", err)
	}
	logger.Debug("created Syft source from directory", "description", src.Describe())

	cfg := syft.DefaultCreateSBOMConfig().WithCatalogerSelection(
		pkgcataloging.NewSelectionRequest().WithDefaults(
			pkgcataloging.ImageTag,
		).WithRemovals(
			"sbom",
			// TODO consider how to turn it on https://github.com/chainguard-dev/internal-dev/issues/8731
			"elf-package",
		),
	).WithCatalogers(
		catalogers.AngularJSReference,
		catalogers.PipVendorReference,
		catalogers.WheelReference,
	)

	createdSBOM, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create SBOM: %w", err)
	}

	packageCollection := createdSBOM.Artifacts.Packages
	packageCollection.Add(*apkPackage)

	if cfg.Relationships.ExcludeBinaryPackagesWithFileOwnershipOverlap {
		// This setting is enabled by default in Syft/Grype. If it's enabled here in
		// this code, we can simulate its behavior in our tailored APK analysis by
		// removing all binary packages from the SBOM, since we know they are all owned
		// by the APK package, and would thus be excluded.

		binaryPkgs := packageCollection.Sorted(pkg.BinaryPkg)
		for i := range binaryPkgs {
			p := binaryPkgs[i]
			logger.Info("removing binary package from SBOM", "name", p.Name, "version", p.Version, "location", p.Locations.CoordinateSet().ToSlice())
			packageCollection.Delete(p.ID())
		}
	}

	logger.Info("finished Syft SBOM generation", "packageCount", packageCollection.PackageCount())

	s := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: packageCollection,
			LinuxDistribution: &linux.Release{
				ID: distroID,
			},
		},
		Source: getDeterministicSourceDescription(src, inputFilePath, apkPackage.Name, apkPackage.Version),
		Descriptor: sbom.Descriptor{
			Name: "wolfictl",
		},
	}

	return &s, nil
}

func getDeterministicSourceDescription(src source.Source, inputFilePath, apkName, apkVersion string) source.Description {
	description := src.Describe()

	description.ID = "(redacted for determinism)"
	description.Name = apkName
	description.Version = apkVersion
	metadata := source.DirectoryMetadata{
		Path: inputFilePath,
	}
	description.Metadata = metadata

	return description
}

func newAPKPackage(r io.Reader, distroID string, includedFiles []string) (*pkg.Package, error) {
	pkginfo, err := parsePkgInfo(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse APK metadata: %w", err)
	}

	files := make([]pkg.ApkFileRecord, 0, len(includedFiles))
	for _, f := range includedFiles {
		files = append(files, pkg.ApkFileRecord{
			Path: f,
		})
	}

	metadata := pkg.ApkDBEntry{
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
		Files:         files,
	}

	p := baseSyftPkgFromPkgInfo(*pkginfo, metadata)

	p.PURL = generatePURL(*pkginfo, distroID)
	p.CPEs = generateSyftCPEs(*pkginfo, p)

	return &p, nil
}

func baseSyftPkgFromPkgInfo(p pkgInfo, metadata any) pkg.Package {
	syftPkg := pkg.Package{
		Name:      p.PkgName,
		Version:   p.PkgVer,
		FoundBy:   "wolfictl",
		Locations: file.NewLocationSet(file.NewLocation(pkginfoPath)),
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense(p.License)),
		Type:      pkg.ApkPkg,
		Metadata:  metadata,
	}

	syftPkg.SetID()

	return syftPkg
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

func generateSyftCPEs(apk pkgInfo, syftPkg pkg.Package) []cpe.CPE {
	if attr := generateWfnAttributesForAPK(apk); attr != nil {
		return []cpe.CPE{{Attributes: cpe.Attributes(*attr), Source: cpeSourceWolfictl}}
	}

	if dictionaryCPE, ok := cpegen.DictionaryFind(syftPkg); ok {
		return dictionaryCPE
	}

	return cpegen.Generate(syftPkg)
}

// ToSyftJSON returns the SBOM as a reader of the Syft JSON format.
func ToSyftJSON(s *sbom.SBOM) (io.ReadSeeker, error) {
	buf := new(bytes.Buffer)

	m := syftjson.ToFormatModel(*s, syftjson.DefaultEncoderConfig())
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(m)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SBOM: %w", err)
	}

	return bytes.NewReader(buf.Bytes()), nil
}

// ToSyftJSONSchemaRedacted returns the SBOM as a reader of the Syft JSON
// format. The returned data has schema information redacted to enable easier
// testing (less noisy diff comparisons).
//
// For most use cases, prefer ToSyftJSON over this function.
func ToSyftJSONSchemaRedacted(s *sbom.SBOM) (io.ReadSeeker, error) {
	buf := new(bytes.Buffer)

	m := syftjson.ToFormatModel(*s, syftjson.DefaultEncoderConfig())
	m.Schema = model.Schema{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(m)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SBOM: %w", err)
	}

	return bytes.NewReader(buf.Bytes()), nil
}

// FromSyftJSON returns an SBOM from a reader of the Syft JSON format.
func FromSyftJSON(r io.ReadSeeker) (*sbom.SBOM, error) {
	s, _, _, err := syftjson.NewFormatDecoder().Decode(r)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Syft JSON: %w", err)
	}

	return s, nil
}
