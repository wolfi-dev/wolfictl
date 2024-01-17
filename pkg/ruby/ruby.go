package ruby

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	ghauth "github.com/cli/go-gh/v2/pkg/auth"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"

	"chainguard.dev/melange/pkg/config"
	http2 "github.com/wolfi-dev/wolfictl/pkg/http"
	"github.com/wolfi-dev/wolfictl/pkg/melange"
)

type RubyOptions struct {
	All bool

	// RubyVersion is the version of Ruby to search for within the wolfi
	// directory. Used to search for packages importing ruby-${RubyVersion}
	RubyVersion string

	// Path is the path to the wolfi directory or a single package to check
	Path string
}

const (
	rubyKey        = "ruby-"
	rubyVersionKey = "required_ruby_version"
	gemspecSuffix  = ".gemspec"
)

type RubyPackage struct {
	Name string
	Repo string
	Ref  string
}

type RubyRepoContext struct {
	Pkg    RubyPackage
	Client *http2.RLHTTPClient
}

type ghTokenSource struct{}

func (ghTokenSource) Token() (*oauth2.Token, error) {
	if tok, _ := ghauth.TokenForHost("github.com"); tok != "" {
		return &oauth2.Token{AccessToken: tok}, nil
	}
	return nil, errors.New("could not find github token")
}

// Operate lists packages.
func Operate(opts RubyOptions) ([]string, error) {
	client := &http2.RLHTTPClient{
		Client: oauth2.NewClient(context.Background(), ghTokenSource{}),

		// 1 request every (n) second(s) to avoid DOS'ing server. https://docs.github.com/en/rest/guides/best-practices-for-integrators?apiVersion=2022-11-28#dealing-with-secondary-rate-limits
		Ratelimiter: rate.NewLimiter(rate.Every(5*time.Second), 1),
	}

	rubyPackages, err := opts.discoverRubyPackages()
	if err != nil {
		return []string{}, fmt.Errorf("discovering packages: %w", err)
	}

	for _, pkg := range rubyPackages {
		fmt.Printf("%s\n", pkg)
		// TODO(@found-it): remove
		if pkg.Name != "ruby3.2-fluentd-1.16" && pkg.Name != "ruby3.2-redis-client" {
			continue
		}
        rctx := RubyRepoContext{
            Pkg: pkg,
            Client: client,
        }

		// Check gemspec for version constraints
        _, err := rctx.Gemspec()
		if err != nil {
			return []string{}, fmt.Errorf("finding gemspec: %w", err)
		}

		// Search for standard library deprecations
		// TODO
	}

	return []string{}, nil
}

func (o *RubyOptions) discoverRubyPackages() ([]RubyPackage, error) {
	pkgs, err := melange.ReadAllPackagesFromRepo(o.Path)
	if err != nil {
		return []RubyPackage{}, fmt.Errorf("Error reading dir, %w", err)
	}

	rubyFiles := []RubyPackage{}
	for _, pkg := range pkgs {
		isRuby, err := o.isRubyPackage(pkg.Config)
		if err != nil {
			return []RubyPackage{}, fmt.Errorf("Error detecting ruby: %w", err)
		}
		if isRuby {
			rubyFiles = append(rubyFiles, RubyPackage{
				Name: pkg.Config.Name(),
				Repo: discoverRepo(pkg),
				Ref:  discoverRef(pkg),
			})
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

func discoverRepo(pkg *melange.Packages) string {
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

func discoverRef(pkg *melange.Packages) string {
	for _, step := range pkg.Config.Pipeline {
		if step.Uses == "git-checkout" {
			if val, ok := step.With["tag"]; ok {
				return strings.Replace(val, "${{package.version}}", pkg.Config.Package.Version, -1)
			}
			if val, ok := step.With["branch"]; ok {
				return strings.Replace(val, "${{package.version}}", pkg.Config.Package.Version, -1)
			}
		}
	}
	return ""
}
