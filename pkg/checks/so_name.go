package checks

import (
	"debug/elf"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	goapk "github.com/chainguard-dev/go-apk/pkg/apk"
	"github.com/wolfi-dev/wolfictl/pkg/apk"
	"github.com/wolfi-dev/wolfictl/pkg/lint"
	"github.com/wolfi-dev/wolfictl/pkg/tar"
	"github.com/wolfi-dev/wolfictl/pkg/versions"
)

type SoNameOptions struct {
	Client              *http.Client
	Logger              *log.Logger
	PackageListFilename string
	Dir                 string
	PackagesDir         string
	PackageNames        []string
	ApkIndexURL         string
	ExistingPackages    map[string]*goapk.Package
}

type NewApkPackage struct {
	Name    string
	Arch    string
	Epoch   string
	Version string
}

func NewSoName() *SoNameOptions {
	o := &SoNameOptions{
		Client: http.DefaultClient,
		Logger: log.New(log.Writer(), "wolfictl check so-name: ", log.LstdFlags|log.Lmsgprefix),
	}

	return o
}

/*
CheckSoName will check if a new APK contains a foo.so file, then compares it with the latest version in an APKINDEX to check
if there are differences.
*/
func (o *SoNameOptions) CheckSoName() error {
	var err error
	apkContext := apk.New(o.Client, o.ApkIndexURL)
	o.ExistingPackages, err = apkContext.GetApkPackages()
	if err != nil {
		return fmt.Errorf("failed to get APK packages from URL %s: %w", o.ApkIndexURL, err)
	}

	// get a list of new package names that have recently been built
	newPackages, err := getNewPackages(o.PackageListFilename)
	if err != nil {
		return fmt.Errorf("failed to get new packages: %w", err)
	}

	soNameErrors := make(lint.EvalRuleErrors, 0)
	// for every new package built lets compare *.so names with the previous released version
	for packageName, newAPK := range newPackages {
		o.Logger.Printf("checking %s", packageName)
		err = o.diff(packageName, newAPK)

		if err != nil {
			soNameErrors = append(soNameErrors, lint.EvalRuleError{
				Error: fmt.Errorf(err.Error()),
			})
		}
	}

	return soNameErrors.WrapErrors()
}

// diff will compare the so name versions between the latest existing apk in a APKINDEX with a newly built local apk
func (o *SoNameOptions) diff(newPackageName string, newAPK NewApkPackage) error {
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
	filename := filepath.Join(o.PackagesDir, newAPK.Arch, fmt.Sprintf("%s-%s-r%s.apk", newPackageName, newAPK.Version, newAPK.Epoch))
	newFile, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", filename, err)
	}

	if err := tar.Untar(newFile, dirNewApk); err != nil {
		return fmt.Errorf("failed to untar new apk: %w", err)
	}

	newSonameFiles, err := o.getSonameFiles(dirNewApk)
	if err != nil {
		return fmt.Errorf("error when looking for soname files in new apk: %w", err)
	}
	// if no .so name files, skip
	if len(newSonameFiles) == 0 {
		return nil
	}

	// fetch current latest apk
	p := o.ExistingPackages[newPackageName]

	if p == nil {
		o.Logger.Printf("no existing package found for %s, skipping so name check", newPackageName)
		return nil
	}
	existingFilename := fmt.Sprintf("%s-%s.apk", p.Name, p.Version)
	err = downloadCurrentAPK(o.Client, o.ApkIndexURL, existingFilename, dirExistingApk)
	if err != nil {
		return fmt.Errorf("failed to download %s using base URL %s: %w", newPackageName, o.ApkIndexURL, err)
	}

	// get any existing so names
	existingSonameFiles, err := o.getSonameFiles(dirExistingApk)
	if err != nil {
		return fmt.Errorf("error when looking for soname files in existing apk: %w", err)
	}

	err = o.checkSonamesMatch(existingSonameFiles, newSonameFiles)
	if err != nil {
		return fmt.Errorf("soname files differ, this can cause an ABI break.  Existing soname files %s, New soname files %s: %w", strings.Join(existingSonameFiles, ","), strings.Join(newSonameFiles, ","), err)
	}

	return nil
}

func (o *SoNameOptions) getSonameFiles(dir string) ([]string, error) {
	reg := regexp.MustCompile(`\.so.(\d+\.)?(\d+\.)?(\*|\d+)`)

	var fileList []string
	err := filepath.Walk(dir, func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		basePath := filepath.Base(path)
		s := reg.FindString(basePath)
		if s != "" {
			fileList = append(fileList, basePath)
		}

		// also check for DT_SONAME
		ef, err := elf.Open(filepath.Join(dir, basePath))
		if err != nil {
			return nil
		}
		defer ef.Close()

		sonames, err := ef.DynString(elf.DT_SONAME)
		// most likely SONAME is not set on this object
		if err != nil {
			return nil
		}

		if len(sonames) > 0 {
			fileList = append(fileList, sonames...)
		}
		return nil
	})

	return fileList, err
}

func (o *SoNameOptions) checkSonamesMatch(existingSonameFiles, newSonameFiles []string) error {
	if len(existingSonameFiles) == 0 {
		o.Logger.Printf("no existing soname files, skipping")
		return nil
	}

	// regex to match version and optional qualifier
	// \d+(\.\d+)* captures version numbers that may have multiple parts separated by dots
	// ([a-zA-Z0-9-_]*) captures optional alphanumeric (including hyphens and underscores) qualifiers
	r := regexp.MustCompile(`(\d+(\.\d+)*)([a-zA-Z0-9-_]*)`)

	// first turn the existing soname files into a map so it is easier to match with
	existingSonameMap := make(map[string]string)
	for _, soname := range existingSonameFiles {
		o.Logger.Printf("checking soname file %s", soname)
		sonameParts := strings.Split(soname, ".so")

		// Find the version and optional qualifier
		matches := r.FindStringSubmatch(sonameParts[1])
		if len(matches) > 0 {
			version := matches[0] // The entire match, including optional qualifier
			existingSonameMap[sonameParts[0]] = version
		}
	}

	// now iterate over new soname files and compare with existing files
	for _, soname := range newSonameFiles {
		sonameParts := strings.Split(soname, ".so")
		name := sonameParts[0]
		versionStr := strings.TrimPrefix(sonameParts[1], ".")
		existingVersionStr := existingSonameMap[name]

		// skip if no matching file
		if existingVersionStr == "" {
			o.Logger.Printf("no existing soname version found for %s, skipping", name)
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
			return fmt.Errorf("soname version check failed, %s has an existing version %s while new package contains a different version %s.  This can cause ABI failures", name, existingVersion, version)
		}
	}
	return nil
}
