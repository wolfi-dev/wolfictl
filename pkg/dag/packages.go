package dag

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/config"
	"github.com/chainguard-dev/clog"
	apk "github.com/chainguard-dev/go-apk/pkg/apk"
)

const (
	Local = "local"
)

// Configuration represents a configuration along with the file that sourced it.
// It can be for an origin package, a subpackage, or something that is provided by a package.
// The Configuration field is a pointer to the actual configuration as parsed from a file. The Path field is the
// path to the file from which the configuration was parsed. The Name and Version fields are the name and version
// of the package, subpackage, or provided item. In the case of an origin package, the Name field
// is the same as the Configuration.Package.Name field, and the Version field is the same as
// the Configuration.Package.Version field with the epoch added as `-r<epoch>`. In the case of a
// subpackage or provided item, the Name and Version fields may be different.
type Configuration struct {
	*config.Configuration
	Path    string
	name    string
	version string

	// the actual package or subpackage name providing this configuration
	// this allows us to distinguish between a subpackge that is providing a virtual and providing itself
	pkg string
}

func (c Configuration) String() string {
	return fmt.Sprintf("%s-%s", c.name, c.version)
}

func (c Configuration) Name() string {
	return c.name
}

func (c Configuration) Version() string {
	return c.version
}

func (c Configuration) Source() string {
	return Local
}

func (c Configuration) FullName() string {
	return fmt.Sprintf("%s-%s-r%d", c.name, c.version, c.Package.Epoch)
}

func (c Configuration) Resolved() bool {
	return true
}

// Packages represents a set of package configurations, including
// the parent, or origin, package, its subpackages, and whatever else it 'provides'.
// It contains references from each such origin package, subpackage and provides
// to the origin config.
//
// It also maintains a list of the origin packages.
//
// It does not try to determine relationships and dependencies between packages. For that,
// pass a Packages to NewGraph.
type Packages struct {
	configs  map[string][]*Configuration
	packages map[string][]*Configuration
	index    map[string]*Configuration
}

var ErrMultipleConfigurations = fmt.Errorf("multiple configurations using the same package name")

func (p *Packages) addPackage(name string, configuration *Configuration) error {
	if _, exists := p.packages[name]; exists {
		return fmt.Errorf("%s: %w", name, ErrMultipleConfigurations)
	}

	p.packages[name] = append(p.packages[name], configuration)

	return nil
}

func (p *Packages) addConfiguration(name string, configuration *Configuration) error {
	p.configs[name] = append(p.configs[name], configuration)
	p.index[configuration.String()] = configuration

	return nil
}

func (p *Packages) addProvides(c *Configuration, provides []string) error {
	for _, prov := range provides {
		pctx := &build.PipelineBuild{
			Build: &build.Build{
				Configuration: *c.Configuration,
			},
			Package: &c.Package,
		}
		template, err := build.MutateWith(pctx, nil)
		if err != nil {
			return err
		}
		for tmpl, val := range template {
			prov = strings.ReplaceAll(prov, tmpl, val)
		}
		name, version := packageNameFromProvides(prov)
		if version == "" {
			version = c.version
		}
		providesc := &Configuration{
			Configuration: c.Configuration,
			Path:          c.Path,
			name:          name,
			version:       version, // provides can have own version or inherit package's version
			pkg:           c.pkg,
		}
		if err := p.addConfiguration(name, providesc); err != nil {
			return err
		}
	}
	return nil
}

// NewPackages reads an fs.FS to get all of the Melange configuration yamls in
// the given directory, and then parses them, including their subpackages and
// 'provides' parameters, to create a Packages struct with all of the
// information, as well as the list of original packages, and, for each such
// package, the source path (yaml) from which it came. The result is a Packages
// struct.
//
// The input is any fs.FS filesystem implementation. Given a directory path, you
// can call NewPackages like this:
//
// NewPackages(ctx, os.DirFS("/path/to/dir"), "/path/to/dir", "./pipelines")
//
// The repetition of the path is necessary because of how the upstream parser in
// melange requires the full path to the directory to be passed in.
func NewPackages(ctx context.Context, fsys fs.FS, dirPath, pipelineDir string) (*Packages, error) {
	log := clog.FromContext(ctx)

	pkgs := &Packages{
		configs:  make(map[string][]*Configuration),
		packages: make(map[string][]*Configuration),
		index:    make(map[string]*Configuration),
	}
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip anything in .github/ and .git/
		if path == ".github" {
			return fs.SkipDir
		}
		if path == ".git" {
			return fs.SkipDir
		}

		// Skip .yam.yaml and .melange.k8s.yaml
		if d.Type().IsRegular() && path == ".yam.yaml" {
			return nil
		}
		if d.Type().IsRegular() && path == ".melange.k8s.yaml" {
			return nil
		}

		// Skip any file that isn't a yaml file
		if !d.Type().IsRegular() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}

		if filepath.Dir(path) != "." && !strings.HasSuffix(path, ".melange.yaml") {
			log.With("path", path).Debug("skipping non-melange YAML file")
			return nil
		}

		p := filepath.Join(dirPath, path)
		buildc, err := config.ParseConfiguration(ctx, p)
		if err != nil {
			return err
		}
		c := &Configuration{
			Configuration: buildc,
			Path:          p,
			name:          buildc.Package.Name,
			version:       fullVersion(&buildc.Package),
			pkg:           buildc.Package.Name,
		}

		name := c.name
		if name == "" {
			return fmt.Errorf("no package name in %q", path)
		}
		if err := pkgs.addConfiguration(name, c); err != nil {
			return err
		}
		if err := pkgs.addPackage(name, c); err != nil {
			return err
		}
		if err := pkgs.addProvides(c, c.Package.Dependencies.Provides); err != nil {
			return err
		}

		for i := range c.Subpackages {
			subpkg := c.Subpackages[i]
			name := subpkg.Name
			if name == "" {
				return fmt.Errorf("empty subpackage name at index %d for package %q", i, c.Package.Name)
			}
			c := &Configuration{
				Configuration: buildc,
				Path:          p,
				name:          name,
				version:       fullVersion(&buildc.Package), // subpackages have same version as origin
				pkg:           name,
			}
			if err := pkgs.addConfiguration(name, c); err != nil {
				return err
			}
			if err := pkgs.addProvides(c, subpkg.Dependencies.Provides); err != nil {
				return err
			}

			// TODO: resolve deps via `uses` for subpackage pipelines.
		}
		// Resolve all `uses` used by the pipeline. This updates the set of
		// .environment.contents.packages so the next block can include those as build deps.
		pctx := &build.PipelineBuild{
			Build: &build.Build{
				PipelineDirs:  []string{pipelineDir},
				Configuration: *c.Configuration,
			},
			Package: &c.Package,
		}
		for i := range c.Pipeline {
			s := &build.PipelineContext{Environment: &pctx.Build.Configuration.Environment, PipelineDirs: []string{pipelineDir}, Pipeline: &c.Pipeline[i]}
			if err := s.ApplyNeeds(ctx, pctx); err != nil {
				return fmt.Errorf("unable to resolve needs for package %s: %w", name, err)
			}
			c.Environment.Contents.Packages = pctx.Build.Configuration.Environment.Contents.Packages
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return pkgs, nil
}

// Config returns the Melange configuration for the package, provides or
// subpackage with the given name, if the package is present in the Graph. If
// it's not present, Config returns an empty list.
//
// Pass packageOnly=true to restruct it just to origin package names.
func (p Packages) Config(name string, packageOnly bool) []*Configuration {
	if p.configs == nil {
		// this would be unexpected
		return nil
	}
	var (
		c  []*Configuration
		ok bool
	)
	if packageOnly {
		c, ok = p.packages[name]
	} else {
		c, ok = p.configs[name]
	}
	if !ok {
		return nil
	}
	list := make([]*Configuration, 0, len(c))
	list = append(list, c...)

	// sort the list by increasing version
	// this should be better about this, perhaps we will use the apko version sorting library in a future revision
	sort.Slice(list, func(i, j int) bool {
		return fullVersion(&list[i].Package) < fullVersion(&list[j].Package)
	})
	return list
}

func (p Packages) ConfigByKey(key string) *Configuration {
	if len(p.index) == 0 {
		return nil
	}
	c, ok := p.index[key]
	if !ok {
		return nil
	}
	return c
}

// PkgConfig returns the melange Configuration for a given package name.
func (p Packages) PkgConfig(pkgName string) *Configuration {
	for _, cfg := range p.packages[pkgName] {
		if pkgName == cfg.Package.Name {
			return cfg
		}
	}
	return nil
}

// PkgInfo returns the build.Package struct for a given package name.
// If no such package name is found in the packages, return nil package and nil error.
func (p Packages) PkgInfo(pkgName string) *config.Package {
	if cfg := p.PkgConfig(pkgName); cfg != nil {
		return &cfg.Package
	}
	return nil
}

// Packages returns a slice of every package and subpackage available in the Packages struct,
// sorted alphabetically and then by version, with each package converted to a *apk.RepositoryPackage.
func (p Packages) Packages() []*Configuration {
	allPackages := make([]*Configuration, 0, len(p.packages))
	for _, byVersion := range p.packages {
		allPackages = append(allPackages, byVersion...)
	}

	// sort for deterministic output
	sort.Slice(allPackages, func(i, j int) bool {
		if allPackages[i].name == allPackages[j].name {
			return allPackages[i].version < allPackages[j].version
		}
		return allPackages[i].name < allPackages[j].name
	})
	return allPackages
}

// PackageNames returns a slice of the names of all packages, sorted alphabetically.
func (p Packages) PackageNames() []string {
	allPackages := make([]string, 0, len(p.packages))
	for name := range p.packages {
		allPackages = append(allPackages, name)
	}

	// sort for deterministic output
	sort.Strings(allPackages)
	return allPackages
}

// Sub returns a new Packages whose members are the named packages or provides that are listed.
// If a listed element is a provides, automatically includes the origin package that provides it.
// If a listed element is a subpackage, automatically includes the origin package that contains it.
// If a listed element does not exist, returns an error.
func (p Packages) Sub(names ...string) (*Packages, error) {
	pkgs := &Packages{
		configs:  make(map[string][]*Configuration),
		index:    make(map[string]*Configuration),
		packages: make(map[string][]*Configuration),
	}
	for _, name := range names {
		if c, ok := p.configs[name]; ok {
			for _, config := range c {
				if err := pkgs.addConfiguration(name, config); err != nil {
					return nil, err
				}
				if err := pkgs.addPackage(name, config); err != nil {
					return nil, err
				}
			}
		} else {
			return nil, fmt.Errorf("package %q not found", name)
		}
	}
	return pkgs, nil
}

func wantArch(have string, want []string) bool {
	if len(want) == 0 {
		return true
	}

	for _, a := range want {
		if a == have {
			return true
		}
	}

	return false
}

// WithArch returns a new Packages whose members are valid for the given arch.
func (p Packages) WithArch(arch string) (*Packages, error) {
	pkgs := &Packages{
		configs:  make(map[string][]*Configuration),
		index:    p.index,
		packages: make(map[string][]*Configuration),
	}

	for name, c := range p.configs {
		for _, config := range c {
			if !wantArch(arch, config.Package.TargetArchitecture) {
				continue
			}
			if err := pkgs.addConfiguration(name, config); err != nil {
				return nil, err
			}
		}
	}

	for name, c := range p.packages {
		for _, config := range c {
			if !wantArch(arch, config.Package.TargetArchitecture) {
				continue
			}
			if err := pkgs.addPackage(name, config); err != nil {
				return nil, err
			}
		}
	}
	return pkgs, nil
}

// Repository provide the Packages as a apk.RepositoryWithIndex. To be used in other places that require
// using alpine/go structs instead of ours.
func (p Packages) Repository(arch string) apk.NamedIndex {
	repo := apk.NewRepositoryFromComponents(Local, "latest", "", arch)

	// Precompute the number of packages to avoid growslice.
	size := 0
	for _, byVersion := range p.packages {
		for _, config := range byVersion {
			size++ // top-level package
			size += len(config.Subpackages)
		}
	}

	packages := make([]*apk.Package, 0, size)
	for _, byVersion := range p.packages {
		for _, cfg := range byVersion {
			cfg := cfg
			packages = append(packages, &apk.Package{
				Arch:         arch,
				Name:         cfg.Package.Name,
				Version:      fullVersion(&cfg.Package),
				Description:  cfg.Package.Description,
				License:      cfg.Package.LicenseExpression(),
				Origin:       cfg.Package.Name,
				URL:          cfg.Package.URL,
				Dependencies: cfg.Environment.Contents.Packages,
				Provides:     cfg.Package.Dependencies.Provides,
				RepoCommit:   cfg.Package.Commit,
			})
			for i := range cfg.Subpackages {
				sub := cfg.Subpackages[i]
				packages = append(packages, &apk.Package{
					Arch:         arch,
					Name:         sub.Name,
					Version:      fullVersion(&cfg.Package),
					Description:  sub.Description,
					License:      cfg.Package.LicenseExpression(),
					Origin:       cfg.Package.Name,
					URL:          cfg.Package.URL,
					Dependencies: cfg.Environment.Contents.Packages,
					Provides:     sub.Dependencies.Provides,
					RepoCommit:   sub.Commit,
				})
			}
		}
	}
	index := &apk.APKIndex{
		Description: "local repository",
		Packages:    packages,
	}

	return apk.NewNamedRepositoryWithIndex("", repo.WithIndex(index))
}

func packageNameFromProvides(prov string) (name, version string) {
	var ok bool
	if name, version, ok = strings.Cut(prov, "~="); ok {
		return
	}
	if name, version, ok = strings.Cut(prov, "="); ok {
		return
	}
	name = prov
	return
}

func fullVersion(pkg *config.Package) string {
	return pkg.Version + "-r" + strconv.FormatUint(pkg.Epoch, 10)
}
