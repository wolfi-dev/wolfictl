package ls

import (
	"fmt"
	"strings"
	"text/template"

	"chainguard.dev/melange/pkg/build"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
)

type ListOptions struct {
	BuildCfgIndices []*configs.Index[build.Configuration]

	// IncludeSubpackages indicates whether subpackages should be included in the results.
	IncludeSubpackages bool

	// RequestedPackages is a list of package names to list. If empty, all packages are listed.
	RequestedPackages []string

	// Template is the Go template string to use when printing results.
	Template string
}

// List lists packages.
func List(opts ListOptions) ([]string, error) {
	var results []string

	var tmpl *template.Template
	if opts.Template != "" {
		var err error
		tmpl, err = template.New("result").Parse(opts.Template)
		if err != nil {
			return nil, fmt.Errorf("unable to parse template: %w", err)
		}
	}

	if len(opts.RequestedPackages) == 0 {
		for _, index := range opts.BuildCfgIndices {
			cfgs := index.Select().Configurations()

			packageNames, err := listPackageNames(cfgs, opts.IncludeSubpackages, tmpl)
			if err != nil {
				return nil, fmt.Errorf("unable to list package names: %w", err)
			}
			results = append(results, packageNames...)
		}

		return results, nil
	}

	for _, requestedPkg := range opts.RequestedPackages {
		var cfgsForRequestedPkg []build.Configuration

		for _, index := range opts.BuildCfgIndices {
			cfgs := index.Select().WhereName(requestedPkg).Configurations()
			cfgsForRequestedPkg = append(cfgsForRequestedPkg, cfgs...)
		}

		if len(cfgsForRequestedPkg) == 0 {
			// If a package was requested that doesn't exist, surface that as an error.
			return nil, fmt.Errorf("no package found for %q", requestedPkg)
		}

		packageNames, err := listPackageNames(cfgsForRequestedPkg, opts.IncludeSubpackages, tmpl)
		if err != nil {
			return nil, fmt.Errorf("unable to list package names: %w", err)
		}
		results = append(results, packageNames...)
	}

	return results, nil
}

// renderResultItem renders a result item using the provided template. If tmpl
// is nil, the package name is returned. The item parameter's type should be
// build.Configuration or build.Subpackage.
func renderResultItem(item any, tmpl *template.Template) (string, error) {
	if tmpl == nil {
		switch item := item.(type) {
		case build.Configuration:
			return item.Package.Name, nil
		case build.Subpackage:
			return item.Name, nil
		default:
			return "", fmt.Errorf("unexpected type %T", item)
		}
	}

	var b strings.Builder
	err := tmpl.Execute(&b, item)
	if err != nil {
		return "", fmt.Errorf("unable to render template: %w", err)
	}

	return b.String(), nil
}

func listPackageNames(cfgs []build.Configuration, includeSubpackages bool, tmpl *template.Template) ([]string, error) {
	var results []string

	for i := range cfgs {
		cfg := cfgs[i]

		rendered, err := renderResultItem(cfg, tmpl)
		if err != nil {
			return nil, err
		}

		results = append(results, rendered)

		if includeSubpackages {
			for i := range cfg.Subpackages {
				subpkg := cfg.Subpackages[i]
				rendered, err := renderResultItem(subpkg, tmpl)
				if err != nil {
					return nil, err
				}

				results = append(results, rendered)
			}
		}
	}

	return results, nil
}
