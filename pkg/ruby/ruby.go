package ruby

import (
	"context"
	"errors"
	"fmt"
	"regexp"
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

	// RubyUpdateVersion is the version of Ruby to update to
	RubyUpdateVersion string

	// Github code search string
	SearchTerm string

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
	Pkg           RubyPackage
	Client        *http2.RLHTTPClient
	UpdateVersion string
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

		// 1 request every (n) second(s) to avoid DOS'ing server.
		// https://docs.github.com/en/rest/guides/best-practices-for-integrators?apiVersion=2022-11-28#dealing-with-secondary-rate-limits
		Ratelimiter: rate.NewLimiter(rate.Every(5*time.Second), 1),
	}

	rubyPackages, err := opts.discoverRubyPackages()
	if err != nil {
		return []string{}, fmt.Errorf("discovering packages: %w", err)
	}

	errors := map[string][]RubyPackage{}
	success := []RubyPackage{}
	for _, pkg := range rubyPackages {
		fmt.Printf("%+v\n", pkg)
		rctx := RubyRepoContext{
			Pkg:           pkg,
			Client:        client,
			UpdateVersion: opts.RubyUpdateVersion,
		}

		// Check gemspec for version constraints
		_, err := rctx.Gemspec()
		if err != nil {
			if _, ok := errors[err.Error()]; !ok {
				errors[err.Error()] = []RubyPackage{}
			}
			errors[err.Error()] = append(errors[err.Error()], pkg)
		} else {
			success = append(success, pkg)
		}

		if opts.SearchTerm != "" {
			// Search for standard library deprecations
			fmt.Printf("Searching with: %s\n", opts.SearchTerm)
			err = rctx.CodeSearch(opts.SearchTerm)
			if err != nil {
				if _, ok := errors[err.Error()]; !ok {
					errors[err.Error()] = []RubyPackage{}
				}
				errors[err.Error()] = append(errors[err.Error()], pkg)
			} else {
				success = append(success, pkg)
			}
		}
		fmt.Printf("\n")
	}

	fmt.Print("----------\n")
	fmt.Print("- FAILED -\n")
	fmt.Print("----------\n")
	for key, val := range errors {
		fmt.Printf("%s\n", key)
		for _, v := range val {
			fmt.Printf("  %s\n", v.Name)
		}
		fmt.Printf("\n")
	}

	fmt.Print("-----------\n")
	fmt.Print("- SUCCESS -\n")
	fmt.Print("-----------\n")
	for _, val := range success {
		fmt.Printf("%s\n", val.Name)
	}

	if len(errors) > 0 {
		return []string{}, fmt.Errorf("Upgrade checks failed")
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
	for _, pkg := range conf.Package.Dependencies.Runtime {
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
		if step.Uses == "fetch" {
			uri := step.With["uri"]
			pattern := `.*\/(v?\$\{{2}package.version\}{2})`
			re := regexp.MustCompile(pattern)
			matches := re.FindStringSubmatch(string(uri))
			if len(matches) > 1 {
				return strings.Replace(matches[1], "${{package.version}}", pkg.Config.Package.Version, -1)
			}
		}
	}
	return ""
}
