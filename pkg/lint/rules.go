package lint

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"

	"chainguard.dev/melange/pkg/renovate"
	"github.com/github/go-spdx/v2/spdxexp"
	"github.com/texttheater/golang-levenshtein/levenshtein"
	"github.com/wolfi-dev/wolfictl/pkg/versions"

	"github.com/dprotaso/go-yit"
	"gopkg.in/yaml.v3"

	"golang.org/x/exp/slices"

	"chainguard.dev/melange/pkg/config"
)

var (
	reValidSHA256 = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	reValidSHA512 = regexp.MustCompile(`^[a-fA-F0-9]{128}$`)
	reValidSHA1   = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	// Be stricter than Go to promote consistency and avoid homograph attacks
	reValidHostname = regexp.MustCompile(`^[a-z0-9][a-z0-9\.\-]+\.[a-z]{2,6}$`)

	forbiddenRepositories = []string{
		"https://packages.wolfi.dev/os",
	}

	forbiddenKeyrings = []string{
		"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub",
	}

	// Used for comparing hosts between configs
	seenHosts = map[string]bool{}
	// The minimum edit distance between two hostnames
	minhostEditDistance = 2
	// Exceptions to the above rule
	hostEditDistanceExceptions = map[string]string{
		"www.libssh.org": "www.libssh2.org",
	}
)

const gitCheckout = "git-checkout"

// AllRules is a list of all available rules to evaluate.
var AllRules = func(l *Linter) Rules { //nolint:gocyclo
	return Rules{
		{
			Name:        "forbidden-repository-used",
			Description: "do not specify a forbidden repository",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
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
			LintFunc: func(config config.Configuration) error {
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
			LintFunc: func(config config.Configuration) error {
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
			LintFunc: func(_ config.Configuration) error {
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
			LintFunc: func(config config.Configuration) error {
				for _, p := range config.Pipeline {
					if p.Uses == "fetch" {
						uri, ok := p.With["uri"]
						if !ok {
							return fmt.Errorf("uri is missing in fetch pipeline")
						}
						u, err := url.ParseRequestURI(uri)
						if err != nil {
							return fmt.Errorf("uri is invalid URL structure")
						}
						if !reValidHostname.MatchString(u.Host) {
							return fmt.Errorf("uri hostname %q is invalid", u.Host)
						}

					}
				}
				return nil
			},
		},
		{
			Name:        "uri-mimic",
			Description: "every config should use a consistent hostname",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
				for _, p := range config.Pipeline {
					uri := p.With["uri"]
					if uri == "" {
						continue
					}
					u, err := url.ParseRequestURI(uri)
					if err != nil {
						// This condition is picked up by valid-pipeline-fetch-uri
						return nil
					}
					host := u.Host
					if seenHosts[host] {
						continue
					}
					for k := range seenHosts {
						// If this becomes a problem, we should filter out hosts that exist in >1 package
						dist := levenshtein.DistanceForStrings([]rune(host), []rune(k), levenshtein.DefaultOptions)
						if hostEditDistanceExceptions[host] == k || hostEditDistanceExceptions[k] == host {
							continue
						}
						if dist <= minhostEditDistance {
							return fmt.Errorf("%q too similar to %q", host, k)
						}

						// Detect TLD swaps
						hostParts := strings.Split(host, ".")
						kParts := strings.Split(k, ".")
						if strings.Join(hostParts[:len(hostParts)-1], ".") == strings.Join(kParts[:len(kParts)-1], ".") {
							return fmt.Errorf("%q shares components with %q", host, k)
						}
					}
					seenHosts[host] = true
				}
				return nil
			},
		},

		{
			Name:        "valid-pipeline-fetch-digest",
			Description: "every fetch pipeline should have a valid digest",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
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
			LintFunc: func(config config.Configuration) error {
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
			LintFunc: func(config config.Configuration) error {
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
			// Bad versioning results in `package file format error` while attempting to install with `apk add`
			ForbidNolint: true,
			LintFunc: func(config config.Configuration) error {
				version := config.Package.Version
				if err := versions.ValidateWithoutEpoch(version); err != nil {
					return fmt.Errorf("invalid version %s, could not parse", version)
				}
				return nil
			},
		},
		{
			Name:        "valid-pipeline-git-checkout-commit",
			Description: "every git-checkout pipeline should have a valid expected-commit",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
				for _, p := range config.Pipeline {
					if p.Uses == gitCheckout {
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
			LintFunc: func(config config.Configuration) error {
				for _, p := range config.Pipeline {
					if p.Uses == gitCheckout {
						if _, ok := p.With["tag"]; !ok {
							return fmt.Errorf("tag is missing")
						}
					}
				}
				return nil
			},
		},
		{
			Name:        "check-when-version-changes",
			Description: "check comments to make sure they are updated when version changes",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
				re := regexp.MustCompile(`# CHECK-WHEN-VERSION-CHANGES: (.+)`)
				var checkString = func(s string) error {
					match := re.FindStringSubmatch(s)
					if len(match) == 0 {
						return nil
					}
					for _, m := range match[1:] {
						if m != config.Package.Version {
							return fmt.Errorf("version in comment: %s does not match version in package: %s, check that it can be updated and update the comment", m, config.Package.Version)
						}
					}
					return nil
				}
				for _, p := range config.Pipeline {
					if err := checkString(p.Runs); err != nil {
						return err
					}
				}
				for _, subPkg := range config.Subpackages {
					for _, subPipeline := range subPkg.Pipeline {
						if err := checkString(subPipeline.Runs); err != nil {
							return err
						}
					}
				}
				return nil
			},
		},
		{
			Name:        "tagged-repository-in-environment-repos",
			Description: "remove tagged repositories like @local from the repositories block",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
				for _, repo := range config.Environment.Contents.Repositories {
					if repo[0] == '@' {
						return fmt.Errorf("repository %q is tagged", repo)
					}
				}
				return nil
			},
		},
		{
			Name:        "git-checkout-must-use-github-updates",
			Description: "when using git-checkout, must use github updates so we can get the expected-commit",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
				for _, p := range config.Pipeline {
					if p.Uses == gitCheckout {
						if config.Update.Enabled && config.Update.GitHubMonitor == nil {
							return fmt.Errorf("configure update.github when using git-checkout")
						}
					}
				}
				return nil
			},
		},
		{
			Name:        "valid-spdx-license",
			Description: "every package should have a valid SPDX license",
			Severity:    SeverityError,
			LintFunc: func(config config.Configuration) error {
				for _, c := range config.Package.Copyright {
					// TODO(jason): make these errors
					if c.License == "" {
						log.Println("license is missing")
						return nil
					}
					if valid, _ := spdxexp.ValidateLicenses([]string{c.License}); !valid {
						log.Printf("license %q is not valid SPDX license", c.License)
						return nil
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
