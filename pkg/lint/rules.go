package lint

import (
	"fmt"
	"net/url"
	"regexp"

	"golang.org/x/exp/slices"

	"chainguard.dev/melange/pkg/build"
)

var (
	reValidSHA256 = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	reValidSHA512 = regexp.MustCompile(`^[a-fA-F0-9]{128}$`)

	forbiddenRepositories = []string{
		"https://packages.wolfi.dev/os",
	}

	forbiddenKeyrings = []string{
		"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub",
	}
)

// AllRules is a list of all available rules to evaluate.
var AllRules = func(l *Linter) Rules {
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
	}
}
