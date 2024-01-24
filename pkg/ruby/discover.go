package ruby

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"chainguard.dev/melange/pkg/config"
	wgit "github.com/wolfi-dev/wolfictl/pkg/git"
	"github.com/wolfi-dev/wolfictl/pkg/melange"
)

type RubyPackage struct {
	// Name is the name of the package, package.name in the melange yaml
	Name string

	// Repo is a URL struct representing the git repo for a ruby package
	Repo *wgit.URL

	// Ref is the version of the ruby package, used to query github
	Ref string
}

// DiscoverRubyPackages searches a given path for melange yaml files using
// packages named ruby-${RubyVersion}. It takes a path to a directory or an
// individual file. A list of RubyPackages will be returned to the caller.
func (o *RubyOptions) DiscoverRubyPackages() ([]RubyPackage, error) {
	ctx := context.Background()
	pkgs, err := melange.ReadAllPackagesFromRepo(ctx, o.Path)
	if err != nil {
		return nil, fmt.Errorf("Error discovering ruby packages, %w", err)
	}

	var rubyFiles []RubyPackage
	for _, pkg := range pkgs {
		if o.isRubyPackage(pkg.Config) {
			gitURL, err := wgit.ParseGitURL(parseRepo(pkg))
			if err != nil {
				// fmt.Printf("
				continue
			}
			rubyFiles = append(rubyFiles, RubyPackage{
				Name: pkg.Config.Name(),
				Repo: gitURL,
				Ref:  parseRef(pkg),
			})
		}
	}

	if len(rubyFiles) < 1 {
		return nil, fmt.Errorf("Did not find any ruby references [%s]", o.Path)
	}

	return rubyFiles, nil
}

// isRubyPackage looks for ruby-${RubyVersion} in the melange yaml package list
func (o *RubyOptions) isRubyPackage(conf config.Configuration) bool {
	rubyPkg := fmt.Sprintf("%s%s", rubyKey, o.RubyVersion)
	rubyDevPkg := fmt.Sprintf("%s-dev", rubyPkg)
	for _, pkg := range conf.Environment.Contents.Packages {
		if pkg == rubyPkg || pkg == rubyDevPkg {
			return true
		}
	}
	for _, pkg := range conf.Package.Dependencies.Runtime {
		if pkg == rubyPkg || pkg == rubyDevPkg {
			return true
		}
	}
	return false
}

// parseRepo tries to extract the repository from the fetch or git-checkout
// pipelines.
//
// TODO: Extract from runs: if neither pipeline is found
func parseRepo(pkg *melange.Packages) string {
	for _, step := range pkg.Config.Pipeline {
		switch step.Uses {
		case "fetch":
			return step.With["uri"]
		case "git-checkout":
			return step.With["repository"]
		}
	}
	return ""
}

// parseRef tries to extract the correct tag/release version string from either
// the fetch or git-checkout pipelines.
func parseRef(pkg *melange.Packages) string {
	ref := ""
	for _, step := range pkg.Config.Pipeline {
		switch step.Uses {
		case "fetch":
			uri := step.With["uri"]
			pattern := `.*\/(v?\$\{{2}package.version\}{2})`
			re := regexp.MustCompile(pattern)
			matches := re.FindStringSubmatch(string(uri))
			if len(matches) > 1 {
				ref = matches[1]
				break
			}
		case "git-checkout":
			if val, ok := step.With["tag"]; ok {
				ref = val
				break
			}
			if val, ok := step.With["branch"]; ok {
				ref = val
				break
			}
		}
	}
	return strings.Replace(ref, "${{package.version}}", pkg.Config.Package.Version, -1)
}
