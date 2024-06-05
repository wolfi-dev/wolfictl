package target

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"

	goapk "github.com/chainguard-dev/go-apk/pkg/apk"
	"github.com/wolfi-dev/wolfictl/pkg/apk"
	"github.com/wolfi-dev/wolfictl/pkg/scan"
	"github.com/wolfi-dev/wolfictl/pkg/versions"
	"go.opentelemetry.io/otel"
)

type Opener struct {
	fsys                   fs.FS
	index                  map[scan.TargetAPK]string
	packageToVersionsIndex map[string][]scan.TargetAPK
}

// New creates a new Opener that can open APK files from the given fs.FS.
func New(ctx context.Context, fsys fs.FS) (*Opener, error) {
	_, span := otel.Tracer("wolfictl").Start(ctx, "scan/target.New")
	defer span.End()

	o := &Opener{
		fsys:                   fsys,
		index:                  make(map[scan.TargetAPK]string),
		packageToVersionsIndex: make(map[string][]scan.TargetAPK),
	}

	err := fs.WalkDir(o.fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if path == "." {
			return nil
		}

		// TODO: consider a recursive option
		if d.IsDir() {
			return fs.SkipDir
		}

		if !d.Type().IsRegular() {
			return nil
		}

		// if extension isn't apk, skip
		if filepath.Ext(path) != ".apk" {
			return nil
		}

		f, err := o.fsys.Open(path)
		if err != nil {
			return fmt.Errorf("opening APK file: %w", err)
		}
		defer f.Close()

		pkginfo, err := apk.PKGINFOFromAPK(f)
		if err != nil {
			return fmt.Errorf("parsing APK file %q: %w", path, err)
		}

		target := pkginfoToTarget(pkginfo)
		o.index[target] = path
		o.packageToVersionsIndex[pkginfo.Name] = append(
			o.packageToVersionsIndex[pkginfo.Name],
			pkginfoToTarget(pkginfo),
		)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return o, nil
}

func pkginfoToTarget(pkginfo *goapk.Package) scan.TargetAPK {
	return scan.TargetAPK{
		Name:              pkginfo.Name,
		Version:           pkginfo.Version,
		OriginPackageName: pkginfo.Origin,
	}
}

// Open opens and returns the APK file for the given target.
func (o Opener) Open(target scan.TargetAPK) (fs.File, error) {
	path, ok := o.index[target]
	if !ok {
		return nil, fmt.Errorf("no APK found for target %v", target)
	}

	return o.fsys.Open(path)
}

// LatestVersion returns the latest version of the APK with the given package
// name that's known to the Opener.
func (o Opener) LatestVersion(name string) (scan.TargetAPK, error) {
	targets, ok := o.packageToVersionsIndex[name]
	if !ok || len(targets) == 0 {
		return scan.TargetAPK{}, fmt.Errorf("no APK found for package named %q", name)
	}

	if len(targets) == 1 {
		return targets[0], nil
	}

	sort.Slice(targets, func(i, j int) bool {
		return versions.Less(targets[i].Version, targets[j].Version)
	})

	return targets[0], nil
}
