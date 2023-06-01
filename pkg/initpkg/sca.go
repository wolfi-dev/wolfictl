package initpkg

import (
	"errors"
	"io/fs"
	"os"
	"strings"

	melange_build "chainguard.dev/melange/pkg/build"
	"github.com/go-enry/go-license-detector/v4/licensedb"
	"github.com/go-enry/go-license-detector/v4/licensedb/filer"
	log "github.com/sirupsen/logrus"
)

// AnalyzeLicenses attempts to deduce the licenses used.
func (ctx *Context) AnalyzeLicenses() ([]string, error) {
	log.Printf("analyzing %s", ctx.WorkDir)

	dir, err := filer.FromDirectory(ctx.WorkDir)
	if err != nil {
		return []string{}, err
	}

	licenses, err := licensedb.Detect(dir)
	if err != nil {
		if errors.Is(err, licensedb.ErrNoLicenseFound) {
			return []string{"TODO"}, nil
		}

		return []string{}, err
	}

	finalLicenses := []string{}
	for spdxID, match := range licenses {
		// Never use deprecated SPDX tags.
		if strings.HasPrefix(spdxID, "deprecated_") {
			continue
		}

		// Cannot really tell between GPL-x-only and GPL-x-or-later, so prefer
		// the -or-later ID, which is the normal one.
		if strings.HasSuffix(spdxID, "-only") {
			continue
		}

		if match.Confidence > 0.9 {
			finalLicenses = append(finalLicenses, spdxID)
			break
		}
	}

	// No licenses, mark it as a TODO item.
	if len(finalLicenses) == 0 {
		return []string{"TODO"}, nil
	}

	log.Printf("determined license %v for %s", finalLicenses, ctx.Build.Package.Name)

	return finalLicenses, nil
}

type LayoutAnalyzer func(*Context, fs.StatFS) error

var ErrUnsupportedLayout = errors.New("unsupported layout")

func analyzeAutoconf(ctx *Context, fsys fs.StatFS) error {
	if _, err := fsys.Stat("configure"); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrUnsupportedLayout
		}
	}

	// We have a configure file, add the configure pipeline.
	configureNode := melange_build.Pipeline{
		Uses: "autoconf/configure",
	}

	buildNode := melange_build.Pipeline{
		Uses: "autoconf/make",
	}

	installNode := melange_build.Pipeline{
		Uses: "autoconf/make-install",
	}

	ctx.Build.Pipeline = append(ctx.Build.Pipeline, configureNode, buildNode, installNode)

	return nil
}

func analyzeCMake(ctx *Context, fsys fs.StatFS) error {
	if _, err := fsys.Stat("CMakeLists.txt"); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrUnsupportedLayout
		}
	}

	// We have a configure file, add the configure pipeline.
	configureNode := melange_build.Pipeline{
		Uses: "cmake/configure",
	}

	buildNode := melange_build.Pipeline{
		Uses: "cmake/build",
	}

	installNode := melange_build.Pipeline{
		Uses: "cmake/install",
	}

	ctx.Build.Pipeline = append(ctx.Build.Pipeline, configureNode, buildNode, installNode)

	return nil
}

func analyzeMeson(ctx *Context, fsys fs.StatFS) error {
	if _, err := fsys.Stat("meson.build"); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrUnsupportedLayout
		}
	}

	// We have a configure file, add the configure pipeline.
	configureNode := melange_build.Pipeline{
		Uses: "meson/configure",
	}

	buildNode := melange_build.Pipeline{
		Uses: "meson/compile",
	}

	installNode := melange_build.Pipeline{
		Uses: "meson/install",
	}

	ctx.Build.Pipeline = append(ctx.Build.Pipeline, configureNode, buildNode, installNode)

	return nil
}

func analyzeGolang(ctx *Context, fsys fs.StatFS) error {
	if _, err := fsys.Stat("go.mod"); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrUnsupportedLayout
		}
	}

	buildNode := melange_build.Pipeline{
		Uses: "go/build",
		With: map[string]string{
			"ldflags":  "-s -w",
			"output":   "${{package.name}}",
			"packages": "./...",
		},
	}

	ctx.Build.Pipeline = append(ctx.Build.Pipeline, buildNode)

	return nil
}

// AnalyzeLayout attempts to deduce the source code layout, adding the appropriate
// build nodes to the pipeline.
func (ctx *Context) AnalyzeLayout() error {
	analyzers := []LayoutAnalyzer{
		analyzeAutoconf,
		analyzeCMake,
		analyzeMeson,
		analyzeGolang,
	}

	// Since Go 1.18, DirFS actually implements StatFS, but it does not return
	// a fs.StatFS.  So we cast it to get our StatFS.
	dirFS := os.DirFS(ctx.WorkDir).(fs.StatFS)

	for _, analyzer := range analyzers {
		if err := analyzer(ctx, dirFS); err != nil {
			if errors.Is(err, ErrUnsupportedLayout) {
				continue
			}

			return err
		}

		break
	}

	// We always want a strip node.
	stripNode := melange_build.Pipeline{
		Uses: "strip",
	}

	ctx.Build.Pipeline = append(ctx.Build.Pipeline, stripNode)

	return nil
}
