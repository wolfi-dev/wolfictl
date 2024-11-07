package checks

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	goapk "chainguard.dev/apko/pkg/apk/apk"
	"github.com/chainguard-dev/clog"
	"github.com/google/go-cmp/cmp"
	"github.com/wolfi-dev/wolfictl/pkg/tar"
)

type DiffOptions struct {
	Client           *http.Client
	Dir              string
	PackagesDir      string
	ApkIndexURL      string
	ExistingPackages map[string]*goapk.Package
}

func NewDiff() *DiffOptions {
	o := &DiffOptions{
		Client: http.DefaultClient,
	}

	return o
}

// Diff compare a newly built apk with the latest in an APK repository, writing the differences to a file diff.log
func (o *DiffOptions) Diff(ctx context.Context, existingPackages, newPackages map[string]*goapk.Package) error {
	log := clog.FromContext(ctx)

	// create two temp folders we can use to explode the apks and compare their contents
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

	// for each new package being built grab the latest existing one
	for _, newAPK := range newPackages {
		log.Infof("checking %s", newAPK.PackageName())
		// read new apk
		filename := filepath.Join(o.PackagesDir, newAPK.Arch, newAPK.PackageName())
		newFile, err := os.Open(filename)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", filename, err)
		}

		if err := tar.Untar(newFile, filepath.Join(dirNewApk, newAPK.PackageName())); err != nil {
			return fmt.Errorf("failed to untar new apk: %w", err)
		}

		// fetch current latest apk
		p, ok := existingPackages[newAPK.PackageName()]
		if !ok {
			if err := os.Mkdir(filepath.Join(dirExistingApk, newAPK.Name), os.ModePerm); err != nil {
				return fmt.Errorf("failed to mkdir %s", filepath.Join(dirExistingApk, newAPK.Name))
			}
			continue
		}

		existingFilename := fmt.Sprintf("%s-%s.apk", p.Name, p.Version)
		if err := downloadCurrentAPK(o.Client, o.ApkIndexURL, existingFilename, filepath.Join(dirExistingApk, newAPK.PackageName())); err != nil {
			return fmt.Errorf("failed to download %s using base URL %s: %w", newAPK.PackageName(), existingFilename, err)
		}
	}

	rs, err := diffDirectories(dirNewApk, dirExistingApk)
	if err != nil {
		return err
	}

	// If malcontent is on the path, then run it to get a capability diff.
	var result []byte
	if path, err := exec.LookPath("mal"); err == nil {
		log.Infof("starting malcontent for %d packages", len(newPackages))
		// --min-file-level=3 filters out lower-risk changes in lower-risk files.
		//
		// As we get more comfortable with the output, we should decrease this value from 3 (HIGH) to 2 (MEDIUM).
		cmd := exec.Command(path, "-quantity-increases-risk=false", "-format=markdown", "-min-risk=critical", "diff", "-file-risk-increase=true", dirExistingApk, dirNewApk)
		result, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("malcontent execution failed with error %w: %s", err, result)
		}
		log.Infof("finished malcontent")
	}

	diffFile := filepath.Join(o.Dir, "diff.log")
	if err := writeDiffLog(rs, result, diffFile, newPackages); err != nil {
		return fmt.Errorf("failed writing to file: %w", err)
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

	// If present, contains .PKGINFO.
	// [0] = before, [1] = after.
	pkginfos []string
}

func diffDirectories(dir1, dir2 string) (diffResult, error) {
	result := diffResult{}

	err := filepath.WalkDir(dir1, func(path1 string, info1 os.DirEntry, err error) error {
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
			if filepath.Base(path1) == ".PKGINFO" {
				content, err := readFileContents(path1)
				if err != nil {
					return err
				}
				result.pkginfos = append(result.pkginfos, content)
			}

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
				if filepath.Base(path1) == ".PKGINFO" {
					result.pkginfos = append(result.pkginfos, content2, content1)
				} else {
					result.modified = append(result.modified, relPath)
				}
			}
		}

		return nil
	})

	if err != nil {
		return diffResult{}, err
	}

	if err := filepath.WalkDir(dir2, func(path2 string, info2 os.DirEntry, err error) error {
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
	}); err != nil {
		return diffResult{}, err
	}

	return result, nil
}

// let's skip wolfi core files
func shouldSkipFile(path string) bool {
	return strings.HasSuffix(path, ".rsa.pub") ||
		strings.HasSuffix(path, ".spdx.json")
}

func writeDiffLog(diff diffResult, mal []byte, filename string, newPackages map[string]*goapk.Package) error {
	var builder strings.Builder

	for packageName := range newPackages {
		builder.WriteString("<details>\n")
		builder.WriteString("  <summary>Package " + packageName + ": Click to expand/collapse</summary>\n")
		builder.WriteString("\n")

		builder.WriteString("Package " + packageName + ":\n")

		var cmpdiff string
		if len(diff.pkginfos) == 1 {
			cmpdiff = diff.pkginfos[0]
		} else if len(diff.pkginfos) == 2 {
			cmpdiff = cmp.Diff(diff.pkginfos[0], diff.pkginfos[1])
		}
		if cmpdiff != "" {
			fmt.Fprintf(&builder, "\n`.PKGINFO` metadata:\n```diff\n%s\n```\n", cmpdiff)
		}

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

	if len(mal) > 0 {
		builder.WriteString("<details>\n")
		builder.WriteString("  <summary>malcontent found differences: Click to expand/collapse</summary>\n\n")
		builder.Write(mal)
		builder.WriteString("\n</details>\n\n")
	}

	content := builder.String()

	return os.WriteFile(filename, []byte(content), 0o644)
}
