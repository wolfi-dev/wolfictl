package checks

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/wolfi-dev/wolfictl/pkg/apk"
	"github.com/wolfi-dev/wolfictl/pkg/tar"
	"gitlab.alpinelinux.org/alpine/go/repository"
)

type DiffOptions struct {
	Client              *http.Client
	Logger              *log.Logger
	PackageListFilename string
	Dir                 string
	PackagesDir         string
	ApkIndexURL         string
	ExistingPackages    map[string]*repository.Package
}

func NewDiff() *DiffOptions {
	o := &DiffOptions{
		Client: http.DefaultClient,
		Logger: log.New(log.Writer(), "wolfictl check diff: ", log.LstdFlags|log.Lmsgprefix),
	}

	return o
}

// Diff compare a newly built apk with the latest in an APK repository, writing the differences to a file diff.log
func (o *DiffOptions) Diff() error {
	// create two temp folders we can use to explode the apks and compare their contents
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

	// get the latest APKINDEX
	apkContext := apk.New(o.Client, o.ApkIndexURL)
	o.ExistingPackages, err = apkContext.GetApkPackages()
	if err != nil {
		return errors.Wrapf(err, "failed to get APK packages from URL %s", o.ApkIndexURL)
	}

	// get a list of new package names that have recently been built
	newPackages, err := getNewPackages(o.PackageListFilename)
	if err != nil {
		return errors.Wrapf(err, "failed to get new packages from file %s", o.PackageListFilename)
	}

	// for each new package being built grab the latest existing one
	for newPackageName, newAPK := range newPackages {
		o.Logger.Printf("checking %s", newPackageName)
		// read new apk
		filename := filepath.Join(o.PackagesDir, newAPK.Arch, fmt.Sprintf("%s-%s-r%s.apk", newPackageName, newAPK.Version, newAPK.Epoch))
		newFile, err := os.Open(filename)
		if err != nil {
			return errors.Wrapf(err, "failed to read %s", filename)
		}

		err = tar.Untar(newFile, filepath.Join(dirNewApk, newPackageName))
		if err != nil {
			return errors.Wrapf(err, "failed to untar new apk")
		}

		// fetch current latest apk
		p, ok := o.ExistingPackages[newPackageName]
		if !ok {
			err = os.Mkdir(filepath.Join(dirExistingApk, newAPK.Name), os.ModePerm)
			if err != nil {
				return fmt.Errorf("failed to mkdir %s", filepath.Join(dirExistingApk, newAPK.Name))
			}
			continue
		}

		existingFilename := fmt.Sprintf("%s-%s.apk", p.Name, p.Version)
		err = downloadCurrentAPK(o.Client, o.ApkIndexURL, existingFilename, filepath.Join(dirExistingApk, newPackageName))
		if err != nil {
			return errors.Wrapf(err, "failed to download %s using base URL %s", newPackageName, existingFilename)
		}
	}

	rs, err := diffDirectories(dirNewApk, dirExistingApk)
	if err != nil {
		return err
	}

	diffFile := filepath.Join(o.Dir, "diff.log")
	err = writeDiffLog(rs, diffFile, newPackages)
	if err != nil {
		return errors.Wrap(err, "failed writing to file")
	}

	fmt.Printf("diff written to %s\n", diffFile)
	return nil
}

func readFileContents(path string) (string, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

type diffResult struct {
	added    []string
	modified []string
	deleted  []string
}

func diffDirectories(dir1, dir2 string) (diffResult, error) {
	result := diffResult{}

	err := filepath.Walk(dir1, func(path1 string, info1 os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info1.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(dir1, path1)
		if err != nil {
			return err
		}

		path2 := filepath.Join(dir2, relPath)

		if shouldSkipFile(path1) {
			return nil
		}

		info2, err := os.Stat(path2)

		if os.IsNotExist(err) {
			result.added = append(result.added, relPath)
		} else if !info2.IsDir() {
			content1, err := readFileContents(path1)
			if err != nil {
				return err
			}

			content2, err := readFileContents(path2)
			if err != nil {
				return err
			}

			if content1 != content2 {
				result.modified = append(result.modified, relPath)
			}
		}

		return nil
	})

	if err != nil {
		return diffResult{}, err
	}

	err = filepath.Walk(dir2, func(path2 string, info2 os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info2.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(dir2, path2)
		if err != nil {
			return err
		}

		path1 := filepath.Join(dir1, relPath)

		if shouldSkipFile(path2) {
			return nil
		}

		_, err = os.Stat(path1)

		if os.IsNotExist(err) {
			result.deleted = append(result.deleted, relPath)
		}

		return nil
	})

	if err != nil {
		return diffResult{}, err
	}

	return result, nil
}

// let's skip wolfi core files
func shouldSkipFile(path string) bool {
	return strings.HasSuffix(path, ".rsa.pub") ||
		strings.EqualFold(filepath.Base(path), ".PKGINFO") ||
		strings.HasSuffix(path, ".spdx.json")
}

func writeDiffLog(diff diffResult, filename string, newPackages map[string]NewApkPackage) error {
	var builder strings.Builder

	for packageName := range newPackages {
		builder.WriteString("<details>\n")
		builder.WriteString("  <summary>Package " + packageName + ": Click to expand/collapse</summary>\n")
		builder.WriteString("\n")

		builder.WriteString("Package " + packageName + ":\n")

		changes := []string{}
		for _, added := range diff.added {
			if strings.HasPrefix(added, packageName+"/") {
				changes = append(changes, "Added: "+strings.TrimPrefix(added, packageName))
			}
		}

		for _, modified := range diff.modified {
			if strings.HasPrefix(modified, packageName+"/") {
				changes = append(changes, "Modified: "+strings.TrimPrefix(modified, packageName))
			}
		}

		for _, deleted := range diff.deleted {
			if strings.HasPrefix(deleted, packageName+"/") {
				changes = append(changes, "Deleted: "+strings.TrimPrefix(deleted, packageName))
			}
		}

		if len(changes) == 0 {
			builder.WriteString("Unchanged\n")
		} else {
			for _, change := range changes {
				builder.WriteString(change + "\n")
			}
		}
		builder.WriteString("\n</details>\n\n")
	}

	content := builder.String()

	return os.WriteFile(filename, []byte(content), os.ModePerm)
}
