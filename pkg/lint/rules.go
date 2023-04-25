package lint

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"chainguard.dev/melange/pkg/renovate"

	"github.com/dprotaso/go-yit"
	"gopkg.in/yaml.v3"

	"golang.org/x/exp/slices"

	"chainguard.dev/melange/pkg/build"
)

var (
	reValidSHA256 = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	reValidSHA512 = regexp.MustCompile(`^[a-fA-F0-9]{128}$`)
	reValidSHA1   = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)

	forbiddenRepositories = []string{
		"https://packages.wolfi.dev/os",
	}

	forbiddenKeyrings = []string{
		"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub",
	}

	// versionRegex how to parse versions.
	// see https://github.com/alpinelinux/apk-tools/blob/50ab589e9a5a84592ee4c0ac5a49506bb6c552fc/src/version.c#
	versionRegex = regexp.MustCompile(`^([0-9]+)((\.[0-9]+)*)([a-z]?)((_alpha|_beta|_pre|_rc)([0-9]*))?((_cvs|_svn|_git|_hg|_p)([0-9]*))?((-r)([0-9]+))?$`)
)

func init() { versionRegex.Longest() }

// AllRules is a list of all available rules to evaluate.
var AllRules = func(l *Linter) Rules { //nolint:gocyclo
	return Rules{
		{
			Name:        "no-makefile-entry-for-package",
			Description: "every package should have a corresponding entry in Makefile",
			Severity:    SeverityError,
			LintFunc: func(config build.Configuration) error {
				exist, err := l.checkMakefile(config.Package.Name)
				if err != nil {
					return err
				}
				if !exist {
					return fmt.Errorf("package %s is not exist in the Makefile", config.Package.Name)
				}
				return nil
			},
			ConditionFuncs: []ConditionFunc{
				l.checkIfMakefileExists(),
			},
		},
		{
			Name:        "forbidden-repository-used",
			Description: "do not specify a forbidden repository",
			Severity:    SeverityError,
			LintFunc: func(config build.Configuration) error {
				for _, repo := range config.Environment.Contents.Repositories {
					if slices.Contains(forbiddenRepositories, repo) {
						return fmt.Errorf("forbidden repository %s is used", repo)
					}
				}
				return nil
			},
		},
		{
			Name:        "forbidden-keyring-used",
			Description: "do not specify a forbidden keyring",
			Severity:    SeverityError,
			LintFunc: func(config build.Configuration) error {
				for _, keyring := range config.Environment.Contents.Keyring {
					if slices.Contains(forbiddenKeyrings, keyring) {
						return fmt.Errorf("forbidden keyring %s is used", keyring)
					}
				}
				return nil
			},
		},
		{
			Name:        "valid-copyright-header",
			Description: "every package should have a valid copyright header",
			Severity:    SeverityInfo,
			LintFunc: func(config build.Configuration) error {
				if len(config.Package.Copyright) == 0 {
					return fmt.Errorf("copyright header is missing")
				}
				for _, c := range config.Package.Copyright {
					if c.License == "" {
						return fmt.Errorf("license is missing")
					}
				}
				return nil
			},
		},
		{
			Name:        "contains-epoch",
			Description: "every package should have an epoch",
			Severity:    SeverityError,
			LintFunc: func(_ build.Configuration) error {
				var node yaml.Node
				fileInfo, err := os.Stat(l.options.Path)
				if err != nil {
					return err
				}

				// only lint files
				if fileInfo.IsDir() {
					return nil
				}

				yamlData, err := os.ReadFile(l.options.Path)
				if err != nil {
					return err
				}

				err = yaml.Unmarshal(yamlData, &node)
				if err != nil {
					return err
				}

				if node.Content == nil {
					return fmt.Errorf("config %s has no yaml content", l.options.Path)
				}

				pkg, err := renovate.NodeFromMapping(node.Content[0], "package")
				if err != nil {
					return err
				}

				if pkg == nil {
					return fmt.Errorf("config %s has no package content", l.options.Path)
				}

				err = containsKey(pkg, "epoch")
				if err != nil {
					return fmt.Errorf("config %s has no package.epoch", l.options.Path)
				}

				return nil
			},
		},
		{
			Name:        "valid-pipeline-fetch-uri",
			Description: "every fetch pipeline should have a valid uri",
			Severity:    SeverityError,
			LintFunc: func(config build.Configuration) error {
				for _, p := range config.Pipeline {
					if p.Uses == "fetch" {
						uri, ok := p.With["uri"]
						if !ok {
							return fmt.Errorf("uri is missing in fetch pipeline")
						}
						if _, err := url.ParseRequestURI(uri); err != nil {
							return fmt.Errorf("uri is invalid URL structure")
						}
					}
				}
				return nil
			},
		},
		{
			Name:        "valid-pipeline-fetch-digest",
			Description: "every fetch pipeline should have a valid digest",
			Severity:    SeverityError,
			LintFunc: func(config build.Configuration) error {
				for _, p := range config.Pipeline {
					if p.Uses == "fetch" {
						hashGiven := false
						if sha256, ok := p.With["expected-sha256"]; ok {
							if !reValidSHA256.MatchString(sha256) {
								return fmt.Errorf("expected-sha256 is not valid SHA256")
							}
							hashGiven = true
						}
						if sha512, ok := p.With["expected-sha512"]; ok {
							if !reValidSHA512.MatchString(sha512) {
								return fmt.Errorf("expected-sha512 is not valid SHA512")
							}
							hashGiven = true
						}
						if !hashGiven {
							return fmt.Errorf("expected-sha256 or expected-sha512 is missing")
						}
					}
				}
				return nil
			},
		},
		{
			Name:        "no-repeated-deps",
			Description: "no repeated dependencies",
			Severity:    SeverityError,
			LintFunc: func(config build.Configuration) error {
				seen := map[string]struct{}{}
				for _, p := range config.Environment.Contents.Packages {
					if _, ok := seen[p]; ok {
						return fmt.Errorf("package %s is duplicated in environment", p)
					}
					seen[p] = struct{}{}
				}
				return nil
			},
		},
		{
			Name:        "bad-template-var",
			Description: "bad template variable",
			Severity:    SeverityError,
			LintFunc: func(config build.Configuration) error {
				badTemplateVars := []string{
					"$pkgdir",
					"$pkgver",
					"$pkgname",
					"$srcdir",
				}

				hasBadVar := func(runs string) error {
					for _, badVar := range badTemplateVars {
						if strings.Contains(runs, badVar) {
							return fmt.Errorf("package contains likely incorrect template var %s", badVar)
						}
					}
					return nil
				}

				for _, s := range config.Pipeline {
					if err := hasBadVar(s.Runs); err != nil {
						return err
					}
				}

				for _, subPkg := range config.Subpackages {
					for _, subPipeline := range subPkg.Pipeline {
						if err := hasBadVar(subPipeline.Runs); err != nil {
							return err
						}
					}
				}
				return nil
			},
		},
		{
			Name:        "bad-version",
			Description: "version is malformed",
			Severity:    SeverityError,
			LintFunc: func(config build.Configuration) error {
				version := config.Package.Version
				if len(versionRegex.FindAllStringSubmatch(version, -1)) == 0 {
					return fmt.Errorf("invalid version %s, could not parse", version)
				}
				return nil
			},
		},
		{
			Name:        "valid-pipeline-git-checkout-commit",
			Description: "every git-checkout pipeline should have a valid expected-commit",
			Severity:    SeverityError,
			LintFunc: func(config build.Configuration) error {
				for _, p := range config.Pipeline {
					if p.Uses == "git-checkout" {
						if commit, ok := p.With["expected-commit"]; ok {
							if !reValidSHA1.MatchString(commit) {
								return fmt.Errorf("expected-commit is not valid SHA1")
							}
						} else {
							return fmt.Errorf("expected-commit is missing")
						}
					}
				}
				return nil
			},
		},
		{
			Name:        "valid-pipeline-git-checkout-tag",
			Description: "every git-checkout pipeline should have a tag",
			Severity:    SeverityError,
			LintFunc: func(config build.Configuration) error {
				for _, p := range config.Pipeline {
					if p.Uses == "git-checkout" {
						if _, ok := p.With["tag"]; !ok {
							return fmt.Errorf("tag is missing")
						}
					}
				}
				return nil
			},
		},
	}
}

func containsKey(parentNode *yaml.Node, key string) error {
	it := yit.FromNode(parentNode).
		ValuesForMap(yit.WithValue(key), yit.All)

	if _, ok := it(); ok {
		return nil
	}

	return fmt.Errorf("key '%s' not found in mapping", key)
}
