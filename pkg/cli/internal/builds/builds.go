package builds

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"

	goapk "chainguard.dev/apko/pkg/apk/apk"
	"github.com/wolfi-dev/wolfictl/pkg/apk"
	"github.com/wolfi-dev/wolfictl/pkg/scan"
)

// Find walks the given filesystem and returns a map of build groups, where each
// group is keyed by the origin package name, and contains the origin package
// and its subpackages. Find expects the filesystem to be laid out just like
// Melange outputs built APKs, starting with a "packages" directory containing
// subdirectories for each architecture, and APK files within those
// subdirectories.
func Find(fsys fs.FS, architectures []string) (map[string]BuildGroup, error) {
	buildsByOrigin := make(map[string]BuildGroup)

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if path == "." {
			return nil
		}

		if d.IsDir() {
			if !slices.Contains(architectures, d.Name()) {
				// This is not an arch directory we care about
				return fs.SkipDir
			}

			return nil
		}

		// This is a file

		if filepath.Ext(d.Name()) != ".apk" {
			// Not an APK file
			return nil
		}

		// This is an APK file

		f, err := fsys.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open file %q: %w", path, err)
		}
		pkginfo, err := apk.PKGINFOFromAPK(f)
		if err != nil {
			return fmt.Errorf("failed to parse APK file %q: %w", path, err)
		}
		fileinfo, err := f.Stat()
		if err != nil {
			return fmt.Errorf("failed to stat file %q: %w", path, err)
		}
		_ = f.Close() // done with the file!

		// Add to the build group

		built := newBuiltPackage(fileinfo, pkginfo, path)
		k := built.buildGroupKey()

		if _, ok := buildsByOrigin[k]; !ok {
			buildsByOrigin[k] = BuildGroup{
				Fsys: fsys,
			}
		}
		bg := buildsByOrigin[k]

		if built.PkgInfo.Name == built.PkgInfo.Origin {
			// This is a top-level package
			bg.Origin = built
		} else {
			// This is a subpackage
			bg.Subpackages = append(bg.Subpackages, built)
		}

		buildsByOrigin[k] = bg

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk packages dir: %w", err)
	}

	return buildsByOrigin, nil
}

// Package describes a built (e.g. by Melange) APK package file that resides on
// a filesystem.
type Package struct {
	// FsysPath is the path to the package file on the filesystem.
	FsysPath string

	// FileInfo is the file info of the package file.
	FileInfo fs.FileInfo

	// PkgInfo is the parsed package information (found in an APK's PKGINFO file).
	PkgInfo *goapk.Package
}

func (p Package) buildGroupKey() string {
	// Construct a key for use in build group maps, using the origin name, (full)
	// version string, and architecture.
	return fmt.Sprintf(
		"%s-%s-%s",
		p.PkgInfo.Origin,
		p.PkgInfo.Version,
		p.PkgInfo.Arch,
	)
}

func newBuiltPackage(fi fs.FileInfo, p *goapk.Package, fsysPath string) Package {
	return Package{
		FsysPath: fsysPath,
		FileInfo: fi,
		PkgInfo:  p,
	}
}

// BuildGroup describes a set of Packages that were produced as a result of a
// Melange build of a package definition, which includes the origin package and
// 0-n subpackages as well.
type BuildGroup struct {
	// Fsys is the filesystem where the build group was found.
	Fsys fs.FS

	Origin      Package
	Subpackages []Package
}

// Scan uses the provided scan.Scanner to scan the APKs in the build group for
// vulnerabilities. It returns a slice of scan results, one for each APK in the
// build group. The first slice member is the result for the origin APK, and the
// rest are for the subpackages.
func (bg BuildGroup) Scan(ctx context.Context, scanner *scan.Scanner, distroID string) ([]scan.Result, error) {
	fsys := bg.Fsys

	targets := append([]Package{bg.Origin}, bg.Subpackages...)

	var results []scan.Result

	for _, target := range targets {
		// TODO: Run these scans in parallel to restore friendship with Jon.

		apkfile, err := fsys.Open(target.FsysPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open APK %q: %w", target.FsysPath, err)
		}

		result, err := scanner.ScanAPK(ctx, apkfile, distroID)
		if err != nil {
			return nil, fmt.Errorf("failed to scan APK %q: %w", target.FsysPath, err)
		}

		results = append(results, *result)
	}

	return results, nil
}
