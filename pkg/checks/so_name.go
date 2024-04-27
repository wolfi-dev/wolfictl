package checks

import (
	"debug/elf"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	goapk "github.com/chainguard-dev/go-apk/pkg/apk"
	"github.com/wolfi-dev/wolfictl/pkg/apk"
	"github.com/wolfi-dev/wolfictl/pkg/lint"
	"github.com/wolfi-dev/wolfictl/pkg/tar"
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

	err = tar.Untar(newFile, dirNewApk)
	if err != nil {
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
		return fmt.Errorf("soname files differ, this can cause an ABI breakage %w", err)
	}

	return nil
}

func (o *SoNameOptions) getSonameFiles(dir string) (map[string][]string, error) {
	reg := regexp.MustCompile(`\.so\.(\d+\.)?(\d+\.)?(\*|\d+)`)

	sonameFiles := make(map[string][]string)
	err := filepath.Walk(dir, func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		basePath := filepath.Base(path)
		s := reg.FindString(basePath)
		if s != "" {
			name := strings.Split(basePath, ".so")[0]
			sonameFiles[name] = append(sonameFiles[name], s)
		}

		ef, err := elf.Open(filepath.Join(dir, basePath))
		if err != nil {
			return nil // Skipping files that can't be opened as ELF files
		}
		defer ef.Close()

		sonames, err := ef.DynString(elf.DT_SONAME)
		if err == nil && len(sonames) > 0 {
			name := strings.Split(sonames[0], ".so")[0]
			sonameFiles[name] = append(sonameFiles[name], sonames[0])
		}
		return nil
	})

	return sonameFiles, err
}

func (o *SoNameOptions) checkSonamesMatch(existingSonameFiles, newSonameFiles map[string][]string) error {
	for name, newVersions := range newSonameFiles {
		existingVersions, exists := existingSonameFiles[name]
		if !exists {
			// Continue if there are no existing versions to compare against, assuming no conflict.
			continue
		}

		for _, newVer := range newVersions {
			versionMatch := false
			for _, existVer := range existingVersions {
				compatible, err := areVersionsCompatible(newVer, existVer)
				if err != nil {
					return fmt.Errorf("error checking version compatibility for %s: %w", name, err)
				}
				if compatible {
					versionMatch = true
					break
				}
			}
			if !versionMatch {
				return fmt.Errorf("soname version mismatch for %s: existing versions %v, new version %s", name, existingVersions, newVer)
			}
		}
	}
	return nil
}

// Example helper function to decide if versions are compatible
func areVersionsCompatible(newVer, existVer string) (bool, error) {
	// Check if either version string is the base "so", which we treat as a wildcard.
	if existVer == "so" {
		return true, nil
	}
	newMajor, err := parseMajorVersion(newVer)
	if err != nil {
		return false, fmt.Errorf("failed to parse new version: %w", err)
	}
	existMajor, err := parseMajorVersion(existVer)
	if err != nil {
		return false, fmt.Errorf("failed to parse existing version: %w", err)
	}
	return newMajor == existMajor, nil
}

// Parses the major version part from a version string
func parseMajorVersion(ver string) (int, error) {
	// Simplified version parsing logic here, assuming version string starts with "so."
	parts := strings.Split(ver, ".")
	if len(parts) < 2 {
		return 0, fmt.Errorf("invalid version format")
	}
	major, err := strconv.Atoi(parts[1]) // Assuming "so.1.2.3" format
	if err != nil {
		return 0, err
	}
	return major, nil
}
