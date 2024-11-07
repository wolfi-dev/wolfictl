package checks

import (
	"archive/tar"
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	goapk "chainguard.dev/apko/pkg/apk/apk"
	"github.com/chainguard-dev/clog"
	"github.com/wolfi-dev/wolfictl/pkg/versions"
	"golang.org/x/exp/maps"
)

type SoNameOptions struct {
	Client      *http.Client
	Dir         string
	PackagesDir string
	ApkIndexURL string
}

func NewSoName() *SoNameOptions {
	o := &SoNameOptions{
		Client: http.DefaultClient,
	}

	return o
}

/*
CheckSoName will check if a new APK contains a foo.so file, then compares it with the latest version in an APKINDEX to check
if there are differences.
*/
func (o *SoNameOptions) CheckSoName(ctx context.Context, existingPackages, newPackages map[string]*goapk.Package) map[string]SoCheckReport {
	log := clog.FromContext(ctx)

	report := map[string]SoCheckReport{}
	// for every new package built lets compare *.so names with the previous released version
	for _, newAPK := range newPackages {
		log.Infof("checking %s", newAPK.Name)

		if err := o.diff(ctx, existingPackages, newAPK); err != nil {
			report[newAPK.Name] = SoCheckReport{
				Package: newAPK,
				Error:   err,
			}
		}
	}

	return report
}

type SoCheckReport struct {
	Package *goapk.Package
	Error   error
}

// diff will compare the so name versions between the latest existing apk in a APKINDEX with a newly built local apk
func (o *SoNameOptions) diff(ctx context.Context, existingPackages map[string]*goapk.Package, newAPK *goapk.Package) error {
	log := clog.FromContext(ctx)

	dirExistingApk, err := os.MkdirTemp("", "wolfictl-apk-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary dir: %w", err)
	}
	defer os.RemoveAll(dirExistingApk)

	dirNewApk, err := os.MkdirTemp("", "wolfictl-apk-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary dir: %w", err)
	}
	defer os.RemoveAll(dirNewApk)

	// read new apk
	filename := filepath.Join(o.PackagesDir, newAPK.Arch, newAPK.PackageName())
	newFile, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", filename, err)
	}

	tr := tar.NewReader(newFile)

	newSonameFiles, err := o.getSonameFiles(tr)
	if err != nil {
		return fmt.Errorf("error when looking for soname files in new apk: %w", err)
	}
	// if no .so name files, skip
	if len(newSonameFiles) == 0 {
		return nil
	}

	// fetch current latest apk
	p := existingPackages[newAPK.Name]

	if p == nil {
		log.Infof("no existing package found for %s, skipping so name check", newAPK.Name)
		return nil
	}
	existingFilename := fmt.Sprintf("%s-%s.apk", p.Name, p.Version)
	if err := downloadCurrentAPK(o.Client, o.ApkIndexURL, existingFilename, dirExistingApk); err != nil {
		return fmt.Errorf("failed to download %s using base URL %s: %w", newAPK.Name, o.ApkIndexURL, err)
	}

	// get any existing so names
	existingSonameFiles, err := o.getSonameFiles(tr)
	if err != nil {
		return fmt.Errorf("error when looking for soname files in existing apk: %w", err)
	}

	if err := o.checkSonamesMatch(ctx, existingPackages, existingSonameFiles, newSonameFiles); err != nil {
		return fmt.Errorf("soname files differ, this can cause an ABI break: %w", err)
	}

	return nil
}

var soFileRE = regexp.MustCompile(`\.so.(\d+\.)?(\d+\.)?(\*|\d+)`)

func (o *SoNameOptions) getSonameFiles(tr *tar.Reader) ([]string, error) {
	var fileList []string
	for {
		th, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("failed to read tar file: %w", err)
		}

		basePath := filepath.Base(th.Name)
		s := soFileRE.FindString(basePath)
		if s != "" {
			fileList = append(fileList, basePath)
		}

		// also check for DT_SONAME
		// TODO(jason): Don't buffer this whole file in memory.
		all, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %w", err)
		}
		ef, err := elf.NewFile(bytes.NewReader(all))
		if err != nil {
			continue
		}
		defer ef.Close()

		sonames, err := ef.DynString(elf.DT_SONAME)
		// most likely SONAME is not set on this object
		if err != nil {
			continue
		}

		if len(sonames) > 0 {
			fileList = append(fileList, sonames...)
		}
	}

	return fileList, nil
}

// ("foo", "1.2.3") -> ["so:foo.so.1", "so:foo.so.1.2", "so:foo.so.1.2.3"]
// This might be naive, I'm sorry if this breaks.
func generateVersions(soname, input string) []string {
	sonames := []string{}
	parts := strings.Split(input, ".")

	for i := range parts {
		sonames = append(sonames, fmt.Sprintf("so:%s.so.%s", soname, strings.Join(parts[0:i+1], ".")))
	}

	return sonames
}

func (o *SoNameOptions) checkSonamesMatch(ctx context.Context, existingPackages map[string]*goapk.Package, existingSonameFiles, newSonameFiles []string) error {
	log := clog.FromContext(ctx)
	if len(existingSonameFiles) == 0 {
		log.Infof("no existing soname files, skipping")
		return nil
	}

	// regex to match version and optional qualifier
	// \d+(\.\d+)* captures version numbers that may have multiple parts separated by dots
	// ([a-zA-Z0-9-_]*) captures optional alphanumeric (including hyphens and underscores) qualifiers
	r := regexp.MustCompile(`(\d+(\.\d+)*)([a-zA-Z0-9-_]*)`)

	// first turn the existing soname files into a map so it is easier to match with
	existingSonameMap := make(map[string]string)
	for _, soname := range existingSonameFiles {
		log.Infof("checking soname file %s", soname)
		sonameParts := strings.Split(soname, ".so")

		// Find the version and optional qualifier
		matches := r.FindStringSubmatch(sonameParts[1])
		if len(matches) > 0 {
			version := matches[0] // The entire match, including optional qualifier
			existingSonameMap[sonameParts[0]] = version
		}
	}

	errs := []error{}
	toBump := map[string]struct{}{}

	// now iterate over new soname files and compare with existing files
	for _, soname := range newSonameFiles {
		sonameParts := strings.Split(soname, ".so")
		name := sonameParts[0]
		versionStr := strings.TrimPrefix(sonameParts[1], ".")
		existingVersionStr := existingSonameMap[name]

		// skip if no matching file
		if existingVersionStr == "" {
			log.Infof("no existing soname version found for %s, skipping", name)
			continue
		}

		// turning the string version into proper version will give us major.minor.patch segments
		existingVersion, err := versions.NewVersion(existingVersionStr)
		if err != nil {
			return fmt.Errorf("failed to parse existing version %s: %w", existingVersionStr, err)
		}

		matches := r.FindStringSubmatch(versionStr)
		if len(matches) > 0 {
			versionStr = matches[0] // The entire match, including optional qualifier
		}

		version, err := versions.NewVersion(versionStr)
		if err != nil {
			return fmt.Errorf("failed to parse new version %s: %w", existingVersionStr, err)
		}

		// let's now compare the major segments as only major version increments indicate a break ABI compatibility
		newVersionMajor := version.Segments()[0]
		existingVersionMajor := existingVersion.Segments()[0]

		if newVersionMajor > existingVersionMajor {
			sonames := generateVersions(name, existingVersionStr)
			for _, pkg := range existingPackages {
				for _, soname := range sonames {
					if slices.Contains(pkg.Dependencies, soname) {
						toBump[pkg.Origin] = struct{}{}
					}
				}
			}

			errs = append(errs, fmt.Errorf("%s: %s -> %s", name, existingVersion, version))
		}
	}

	if len(toBump) != 0 {
		errs = append(errs, fmt.Errorf("to fix this, run:\nwolfictl bump %s", strings.Join(maps.Keys(toBump), " ")))
	}

	return errors.Join(errs...)
}
