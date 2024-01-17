package ruby

import (
	"fmt"
	"strings"

	"chainguard.dev/melange/pkg/config"
	"github.com/wolfi-dev/wolfictl/pkg/melange"
)

type RubyOptions struct {
	All         bool

    // RubyVersion is the version of Ruby to search for within the wolfi
    // directory. Used to search for packages importing ruby-${RubyVersion}
	RubyVersion string

    // Path is the path to the wolfi directory or a single package to check
	Path        string
}

const (
	rubyKey = "ruby-"
)

// Operate lists packages.
func Operate(opts RubyOptions) ([]string, error) {
	return opts.discoverPackages()
}

func (o *RubyOptions) discoverPackages() ([]string, error) {
	pkgs, err := melange.ReadAllPackagesFromRepo(o.Path)
	if err != nil {
		return []string{}, fmt.Errorf("Error reading dir, %w", err)
	}

	rubyFiles := []string{}
	for _, pkg := range pkgs {
		isRuby, err := o.isRubyPackage(pkg.Config)
		if err != nil {
			return []string{}, fmt.Errorf("Error detecting ruby: %w", err)
		}
		if isRuby {
			rubyFiles = append(rubyFiles, pkg.Filename)
		}
	}
	return rubyFiles, nil
}

func (o *RubyOptions) isRubyPackage(conf config.Configuration) (bool, error) {
	for _, pkg := range conf.Environment.Contents.Packages {
		if strings.Contains(pkg, rubyKey+o.RubyVersion) {
			return true, nil
		}
	}
	return false, nil
}
