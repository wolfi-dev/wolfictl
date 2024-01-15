package deps

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/util"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"golang.org/x/exp/slices"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
	versionutil "k8s.io/apimachinery/pkg/util/version"
)

func gitCheckout(p *config.Pipeline, dir string, mutations map[string]string) error {
	repoValue := p.With["repository"]
	if repoValue == "" {
		return fmt.Errorf("no repository to checkout")
	}

	tagValue := p.With["tag"]
	if tagValue == "" {
		return fmt.Errorf("no tag to checkout")
	}

	// evaluate var substitutions
	evaluatedTag, err := util.MutateStringFromMap(mutations, tagValue)
	if err != nil {
		return err
	}

	cloneOpts := &git.CloneOptions{
		URL:               repoValue,
		ReferenceName:     plumbing.ReferenceName(fmt.Sprintf("refs/tags/%s", evaluatedTag)),
		Progress:          os.Stdout,
		RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
		RemoteName:        "origin",
		Depth:             1,
	}

	log.Printf("cloning sources from %s tag %s into a temporary directory '%s', this may take a while", repoValue, dir, evaluatedTag)

	r, err := git.PlainClone(dir, false, cloneOpts)
	if err != nil {
		return fmt.Errorf("failed to clone %s ref %s with error: %v", repoValue, evaluatedTag, err)
	}
	if r == nil {
		return fmt.Errorf("clone is empty %s ref %s", repoValue, evaluatedTag)
	}
	log.Println("git-checkout was successful")

	return nil
}

func cleanupGoBumpPipelineDeps(p *config.Pipeline, tempDir string, tidy bool) error {
	modroot := ""
	if _, ok := p.With["modroot"]; ok {
		modroot = p.With["modroot"]
	}
	goVersion := ""
	if _, ok := p.With["go-version"]; ok {
		goVersion = p.With["go-version"]
	}
	if tidy {
		output, err := goModTidy(path.Join(tempDir, modroot), goVersion)
		if err != nil {
			return fmt.Errorf("failed to run 'go mod tidy': %v with output: %v", err, output)
		}
	}
	// Read the entire go.mod one more time into memory and check that all the version constraints are met.
	modpath := path.Join(tempDir, modroot, "go.mod")
	modFile, err := parseGoModfile(modpath)
	if err != nil {
		return fmt.Errorf("unable to parse the go mod file with error: %v", err)
	}

	replaces := []string{}
	deps := []string{}
	if len(p.With["replaces"]) > 0 {
		replaces = strings.Split(p.With["replaces"], " ")
	}
	pkgReplaceVersions := map[string]string{}
	for _, pkg := range replaces {
		replacePkg := strings.Split(pkg, "=")
		parts := strings.Split(replacePkg[1], "@")
		pkgReplaceVersions[parts[0]] = parts[1]
	}

	if len(p.With["deps"]) > 0 {
		deps = strings.Split(p.With["deps"], " ")
	}

	pkgRequireVersions := map[string]string{}
	for _, pkg := range deps {
		parts := strings.Split(pkg, "@")
		pkgRequireVersions[parts[0]] = parts[1]
	}

	// Detect if the list of packages contain any replace statement
	for _, replace := range modFile.Replace {
		if replace != nil {
			if _, ok := pkgRequireVersions[replace.New.Path]; ok {
				if semver.IsValid(pkgRequireVersions[replace.New.Path]) {
					if semver.Compare(replace.New.Version, pkgRequireVersions[replace.New.Path]) >= 0 {
						idx := slices.Index(deps, fmt.Sprintf("%s=%s@%s", replace.New.Path, replace.New.Path, pkgRequireVersions[replace.New.Path]))
						deps = append(deps[:idx], deps[idx+1:]...)
					}
				}
			}
			if _, ok := pkgReplaceVersions[replace.New.Path]; ok {
				if semver.IsValid(pkgReplaceVersions[replace.New.Path]) {
					if semver.Compare(replace.New.Version, pkgReplaceVersions[replace.New.Path]) >= 0 {
						// TODO(hectorj2f): Assume that the source is the same
						idx := slices.Index(replaces, fmt.Sprintf("%s=%s@%s", replace.New.Path, replace.New.Path, pkgReplaceVersions[replace.New.Path]))
						replaces = append(replaces[:idx], replaces[idx+1:]...)
					}
				}
			}
		}
	}
	// Detect if the list of packages contain any require statement for the package
	for _, require := range modFile.Require {
		if require != nil {
			if _, ok := pkgRequireVersions[require.Mod.Path]; ok {
				if semver.IsValid(pkgRequireVersions[require.Mod.Path]) {
					if semver.Compare(require.Mod.Version, pkgRequireVersions[require.Mod.Path]) >= 0 {
						idx := slices.Index(deps, fmt.Sprintf("%s@%s", require.Mod.Path, pkgRequireVersions[require.Mod.Path]))
						deps = append(deps[:idx], deps[idx+1:]...)
					}
				}
			}
			if _, ok := pkgReplaceVersions[require.Mod.Path]; ok {
				if semver.IsValid(pkgReplaceVersions[require.Mod.Path]) {
					if semver.Compare(require.Mod.Version, pkgReplaceVersions[require.Mod.Path]) >= 0 {
						// TODO(hectorj2f): Assume that the source is the same
						idx := slices.Index(replaces, fmt.Sprintf("%s=%s@%s", require.Mod.Path, require.Mod.Path, pkgReplaceVersions[require.Mod.Path]))
						replaces = append(replaces[:idx], replaces[idx+1:]...)
					}
				}
			}
		}
	}
	if len(pkgRequireVersions) > 0 {
		p.With["deps"] = strings.TrimSpace(strings.Join(deps, " "))
	}

	if len(pkgReplaceVersions) > 0 {
		p.With["replaces"] = strings.TrimSpace(strings.Join(replaces, " "))
	}

	log.Printf("New [deps]: %v\n", p.With["deps"])
	log.Printf("New [replaces]: %v\n", p.With["replaces"])

	return nil
}

func CleanupGoBumpDeps(updated *config.Configuration, tidy bool, mutations map[string]string) error {
	tempDir, err := os.MkdirTemp("", "wolfibump")
	if err != nil {
		return fmt.Errorf("failed to create temporary folder to clone package configs into: %w", err)
	}
	checkedOut := false
	for i := range updated.Pipeline {
		// TODO(hectorj2f): add support for fetch pipelines
		if updated.Pipeline[i].Uses == "git-checkout" {
			err := gitCheckout(&updated.Pipeline[i], tempDir, mutations)
			if err != nil {
				return fmt.Errorf("failed to git checkout the repository: %v", err)
			}
			checkedOut = true
		}
		if checkedOut && updated.Pipeline[i].Uses == "go/bump" {
			// get the go/bump pipeline
			if err := cleanupGoBumpPipelineDeps(&updated.Pipeline[i], tempDir, tidy); err != nil {
				return err
			}
			if updated.Pipeline[i].With["deps"] == "" && updated.Pipeline[i].With["replaces"] == "" {
				log.Printf("deleting the pipeline: %v", updated.Pipeline[i])
				updated.Pipeline = slices.Delete(updated.Pipeline, i, (i + 1))
			}
		}
	}

	return nil
}

func parseGoModfile(file string) (*modfile.File, error) {
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	mod, err := modfile.Parse("go.mod", content, nil)
	if err != nil {
		return nil, err
	}

	return mod, nil
}

func goModTidy(modroot, goVersion string) (string, error) {
	if goVersion == "" {
		cmd := exec.Command("go", "env", "GOVERSION")
		cmd.Stderr = os.Stderr
		out, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("%v: %w", cmd, err)
		}
		goVersion = strings.TrimPrefix(strings.TrimSpace(string(out)), "go")

		v := versionutil.MustParseGeneric(goVersion)
		goVersion = fmt.Sprintf("%d.%d", v.Major(), v.Minor())

		log.Printf("Running go mod tidy with go version '%s' ...\n", goVersion)
	}

	cmd := exec.Command("go", "mod", "tidy", "-go", goVersion)
	cmd.Dir = modroot
	if bytes, err := cmd.CombinedOutput(); err != nil {
		return strings.TrimSpace(string(bytes)), err
	}
	return "", nil
}
