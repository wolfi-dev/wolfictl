package checks

import (
	"bufio"
	"debug/elf"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/wolfi-dev/wolfictl/pkg/versions"

	"github.com/wolfi-dev/wolfictl/pkg/tar"

	"github.com/wolfi-dev/wolfictl/pkg/lint"

	"github.com/wolfi-dev/wolfictl/pkg/apk"

	"github.com/pkg/errors"
	"gitlab.alpinelinux.org/alpine/go/repository"
)

type SoNameOptions struct {
	Client              *http.Client
	Logger              *log.Logger
	PackageListFilename string
	Dir                 string
	PackagesDir         string
	PackageNames        []string
	ApkIndexURL         string
	ExistingPackages    map[string]*repository.Package
}

type NewApkPackage struct {
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
		return errors.Wrapf(err, "failed to get APK packages from URL %s", o.ApkIndexURL)
	}

	// get a list of new package names that have recently been built
	newPackages, err := o.getNewPackages()
	if err != nil {
		return errors.Wrapf(err, "failed to get new packages")
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

// the wolfi package repo CI will write a file entry for every new .apk package that's been built
// in the form $ARCH|$PACKAGE_NAME|$VERSION_r$EPOCH
func (o *SoNameOptions) getNewPackages() (map[string]NewApkPackage, error) {
	rs := make(map[string]NewApkPackage)
	original, err := os.Open(o.PackageListFilename)
	if err != nil {
		return rs, errors.Wrapf(err, "opening file %s", o.PackageListFilename)
	}

	scanner := bufio.NewScanner(original)
	defer original.Close()
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		parts := strings.Split(scanner.Text(), "|")

		if len(parts) != 4 {
			return rs, fmt.Errorf("expected 3 parts but found %d when scanning %s", len(parts), scanner.Text())
		}
		versionParts := strings.Split(parts[3], "-")
		if len(versionParts) != 2 {
			return rs, fmt.Errorf("expected 2 version parts but found %d", len(versionParts))
		}

		arch := parts[0]
		packageName := parts[2]
		version := versionParts[0]

		epoch := versionParts[1]
		epoch = strings.TrimPrefix(epoch, "r")
		epoch = strings.TrimSuffix(epoch, ".apk")

		rs[packageName] = NewApkPackage{
			Version: version,
			Epoch:   epoch,
			Arch:    arch,
		}
	}

	return rs, nil
}

// diff will compare the so name versions between the latest existing apk in a APKINDEX with a newly built local apk
func (o *SoNameOptions) diff(newPackageName string, newAPK NewApkPackage) error {
	dirExistingApk, err := os.MkdirTemp("", "wolfictl-apk-*")
	if err != nil {
		return errors.Wrapf(err, "failed to create temporary dir")
	}
	defer os.RemoveAll(dirExistingApk)

	dirNewApk, err := os.MkdirTemp("", "wolfictl-apk-*")
	if err != nil {
		return errors.Wrapf(err, "failed to create temporary dir")
	}
	defer os.RemoveAll(dirNewApk)

	// read new apk
	filename := filepath.Join(o.PackagesDir, newAPK.Arch, fmt.Sprintf("%s-%s-r%s.apk", newPackageName, newAPK.Version, newAPK.Epoch))
	newFile, err := os.Open(filename)
	if err != nil {
		return errors.Wrapf(err, "failed to read %s", filename)
	}

	err = tar.Untar(newFile, dirNewApk)
	if err != nil {
		return errors.Wrapf(err, "failed to untar new apk")
	}

	newSonameFiles, err := o.getSonameFiles(dirNewApk)
	if err != nil {
		return errors.Wrapf(err, "error when looking for soname files in new apk")
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
	err = o.downloadCurrentAPK(existingFilename, dirExistingApk)
	if err != nil {
		return errors.Wrapf(err, "failed to download %s using base URL %s", newPackageName, o.ApkIndexURL)
	}

	// get any existing so names
	existingSonameFiles, err := o.getSonameFiles(dirExistingApk)
	if err != nil {
		return errors.Wrapf(err, "error when looking for soname files in existing apk")
	}

	err = o.checkSonamesMatch(existingSonameFiles, newSonameFiles)
	if err != nil {
		return errors.Wrapf(err, "soname files differ, this can cause an ABI break.  Existing soname files %s, New soname files %s", strings.Join(existingSonameFiles, ","), strings.Join(newSonameFiles, ","))
	}

	return nil
}

func (o *SoNameOptions) downloadCurrentAPK(newPackageName, dirCurrentApk string) error {
	apkURL := strings.ReplaceAll(o.ApkIndexURL, "APKINDEX", newPackageName)
	resp, err := o.Client.Get(apkURL)
	if err != nil {
		return errors.Wrapf(err, "failed to get %s", apkURL)
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create(filepath.Join(dirCurrentApk, newPackageName))
	if err != nil {
		return err
	}
	defer out.Close()

	// Writer the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}
	return nil
}

func (o *SoNameOptions) getSonameFiles(dir string) ([]string, error) {
	reg := regexp.MustCompile(`\.so.(\d+\.)?(\d+\.)?(\*|\d+)`)

	var fileList []string
	err := filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		s := reg.FindString(filepath.Base(path))
		if s != "" {
			fileList = append(fileList, path)
		}

		// also check for DT_SONAME
		ef, err := elf.Open(filepath.Join(dir, path))
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
	// first turn the existing soname files into a map so it is easier to match with
	existingSonameMap := make(map[string]string)
	for _, soname := range existingSonameFiles {
		o.Logger.Printf("checking soname file %s", soname)
		sonameParts := strings.Split(soname, ".so")
		existingSonameMap[sonameParts[0]] = strings.TrimPrefix(sonameParts[1], ".")
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
			return errors.Wrapf(err, "failed to parse existing version %s", existingVersionStr)
		}

		version, err := versions.NewVersion(versionStr)
		if err != nil {
			return errors.Wrapf(err, "failed to parse new version %s", existingVersionStr)
		}

		// let's now compare the major segments as only major version increments indicate a break ABI compatability
		newVersionMajor := version.Segments()[0]
		existingVersionMajor := existingVersion.Segments()[0]
		if newVersionMajor > existingVersionMajor {
			return fmt.Errorf("soname version check failed, %s has an existing version %s while new package contains a different version %s.  This can cause ABI failures", name, existingVersion, version)
		}
	}
	return nil
}
