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
	"strings"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	cpegen "github.com/anchore/syft/syft/pkg/cataloger/common/cpe"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/chainguard-dev/clog"
	"github.com/package-url/packageurl-go"
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

	// Sanity check: count the number of files in the temp directory. Create an fs.FS and walk it.

	tempFsys := os.DirFS(tempDir)
	err = fs.WalkDir(tempFsys, ".", func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		logger.Debug("apk temp directory item", "path", path)

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
	apkPackage, err := newAPKPackage(pkginfo, distroID)
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
		),
	)

	createdSBOM, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create SBOM: %w", err)
	}

	packageCollection := createdSBOM.Artifacts.Packages
	packageCollection.Add(*apkPackage)

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

func newAPKPackage(r io.Reader, distroID string) (*pkg.Package, error) {
	pkginfo, err := parsePkgInfo(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse APK metadata: %w", err)
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
	}

	p := pkg.Package{
		Name:      pkginfo.PkgName,
		Version:   pkginfo.PkgVer,
		FoundBy:   "wolfictl",
		Locations: file.NewLocationSet(file.NewLocation(pkginfoPath)),
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense(pkginfo.License)),
		Type:      pkg.ApkPkg,
		Metadata:  metadata,
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
		return dictionaryCPE
	}

	// TODO: This is a workaround for Syft not coming up with this CPE for OpenJDK
	// 	packages. Some thought would be needed on the "right" way to implement this
	// 	upstream, but it's more obvious how we can address this in wolfictl for our
	// 	purposes.
	//
	//  Potentially related: https://github.com/anchore/syft/issues/2422
	if strings.HasPrefix(p.Name, "openjdk-") {
		return []cpe.CPE{
			{
				Attributes: cpe.Attributes{
					Part:    "a",
					Vendor:  "oracle",
					Product: "jdk",
					Version: p.Version,
				},
				Source: cpeSourceWolfictl,
			},
		}
	}

	return cpegen.Generate(p)
}

// ToSyftJSON returns the SBOM as a reader of the Syft JSON format.
func ToSyftJSON(s *sbom.SBOM) (io.ReadSeeker, error) {
	buf := new(bytes.Buffer)

	model := syftjson.ToFormatModel(*s, syftjson.DefaultEncoderConfig())
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(model)
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
