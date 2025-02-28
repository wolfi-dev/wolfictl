package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"

	"chainguard.dev/melange/pkg/config"
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
	"github.com/facebookincubator/nvdtools/wfn"
	"github.com/package-url/packageurl-go"
	anchorelogger "github.com/wolfi-dev/wolfictl/pkg/anchorelog"
	"github.com/wolfi-dev/wolfictl/pkg/sbom/catalogers"
	"github.com/wolfi-dev/wolfictl/pkg/tar"
	"gopkg.in/yaml.v3"
)

const (
	cpeSourceWolfictl             cpe.Source = "wolfictl"
	cpeSourceMelangeConfiguration cpe.Source = "melange-configuration"
)

// Generate creates an SBOM for the given APK file.
func Generate(ctx context.Context, inputFilePath string, f io.Reader, distroID string) (*sbom.SBOM, error) {
	log := clog.FromContext(ctx)

	log.Info("generating SBOM for APK file", "path", inputFilePath, "distroID", distroID)

	// Create a temp directory to house the unpacked APK file
	tempDir, err := os.MkdirTemp("", "wolfictl-sbom-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer func() {
		log.Debug("cleaning up temp directory", "path", tempDir)
		_ = os.RemoveAll(tempDir)
	}()

	log.Debug("created temp directory to unpack APK", "path", tempDir)

	// Unpack apk to temp directory
	if err := tar.Untar(f, tempDir); err != nil {
		return nil, fmt.Errorf("failed to unpack apk file: %w", err)
	}
	log.Debug("unpacked APK file to temp directory", "apkFilePath", inputFilePath)

	// Sanity check: count the number of files in the temp directory. Create an
	// fs.FS and walk it. We'll also use this to attach a list of files to the APK
	// package.

	var includedFiles []string

	tempFsys := os.DirFS(tempDir)
	err = fs.WalkDir(tempFsys, ".", func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		log.Debug("apk temp directory item", "path", path)
		includedFiles = append(includedFiles, path)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking APK's temp directory: %w", err)
	}

	// Analyze the APK metadata
	pkginfo, err := os.Open(path.Join(tempDir, pkginfoPath))
	if err != nil {
		return nil, fmt.Errorf("opening %q: %w", pkginfoPath, err)
	}
	defer pkginfo.Close()

	var melangeConfiguration io.Reader
	{
		cfg, err := os.Open(path.Join(tempDir, melangeConfigurationPath))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				// Seeing a different error here would be unexpected — bubble it up.
				return nil, fmt.Errorf("opening melange configuration file: %w", err)
			}

			// This is okay, older APKs don't have this file.
			log.Info("melange configuration not found in APK", "inputFilePath", inputFilePath)
		} else {
			log.Debug("opened melange configuration file within APK", "path", melangeConfigurationPath)
			melangeConfiguration = cfg
		}
	}

	apkPackage, err := newAPKPackage(ctx, pkginfo, melangeConfiguration, distroID, includedFiles)
	if err != nil {
		return nil, fmt.Errorf("creating APK package: %w", err)
	}
	log.Debug("synthesized APK package for SBOM", "name", apkPackage.Name, "version", apkPackage.Version, "id", string(apkPackage.ID()))

	src, err := directorysource.New(
		directorysource.Config{
			Path: tempDir,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create source from directory: %w", err)
	}
	log.Debug("created Syft source from directory", "description", src.Describe())

	syft.SetLogger(anchorelogger.NewSlogAdapter(log.Base()))

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
			log.Info("removing binary package from SBOM", "name", p.Name, "version", p.Version, "location", p.Locations.CoordinateSet().ToSlice())
			packageCollection.Delete(p.ID())
		}
	}

	log.Info("finished Syft SBOM generation", "packageCount", packageCollection.PackageCount())

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

func newAPKPackage(
	ctx context.Context,
	pkginfoReader io.Reader,
	melangeConfigurationReader io.Reader,
	distroID string,
	includedFiles []string,
) (*pkg.Package, error) {
	log := clog.FromContext(ctx)
	pkginfo, err := parsePkgInfo(pkginfoReader)
	if err != nil {
		return nil, fmt.Errorf("parsing APK metadata: %w", err)
	}
	var attr *wfn.Attributes
	if melangeConfigurationReader != nil {
		c, err := extractCPEFromMelangeConfiguration(melangeConfigurationReader)
		if err != nil {
			return nil, fmt.Errorf("extracting CPE from melange configuration: %w", err)
		}
		log.Info("extracted CPE from melange configuration", "cpe", c.BindToFmtString())
		attr = c
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

	if attr != nil {
		// The APK package is providing its own CPE data, so we'll use that instead of
		// trying to determine the CPE on its behalf.

		// Don't forget to use the package's version!
		attr.Version = pkginfo.PkgVer

		p.CPEs = []cpe.CPE{{Attributes: cpe.Attributes(*attr), Source: cpeSourceMelangeConfiguration}}
		log.Debug("using CPE from melange configuration", "cpe", attr.BindToFmtString())
	} else {
		p.CPEs = generateSyftCPEs(*pkginfo, p)

		fmtStrs := make([]string, len(p.CPEs))
		for i := range p.CPEs {
			attr := p.CPEs[i].Attributes
			fmtStrs[i] = attr.BindToFmtString()
		}
		log.Debug("no CPEs found in melange configuration, generated CPEs", "cpes", strings.Join(fmtStrs, ";"))
	}

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

type minimalMelangeConfiguration struct {
	Package config.Package `yaml:"package"`
}

// extractCPEFromMelangeConfiguration extracts the CPE from a melange
// configuration file. If the melange configuration file does not contain a CPE,
// this function returns nil.
//
// NOTE: This function DOES NOT set the CPE version field; this MUST be set by
// the caller.
func extractCPEFromMelangeConfiguration(melangeConfigurationReader io.Reader) (*wfn.Attributes, error) {
	var cfg minimalMelangeConfiguration
	if err := yaml.NewDecoder(melangeConfigurationReader).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("minimal decode of melange configuration: %w", err)
	}

	c := cfg.Package.CPE
	if c.IsZero() {
		return nil, nil
	}

	if c.Part == "" {
		c.Part = "a"
	}

	return &wfn.Attributes{
		Part:      c.Part,
		Vendor:    c.Vendor,
		Product:   c.Product,
		Version:   "", // Should be set by the caller, preferably using data from .PKGINFO.
		Update:    "", // We intentionally don't set this. We can revisit this if we ever have a need for this field.
		Edition:   c.Edition,
		SWEdition: c.SWEdition,
		TargetSW:  c.TargetSW,
		TargetHW:  c.TargetHW,
		Other:     c.Other,
		Language:  c.Language,
	}, nil
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
