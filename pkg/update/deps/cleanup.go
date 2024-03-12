package deps

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	wgit "github.com/wolfi-dev/wolfictl/pkg/git"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/util"
	"github.com/dprotaso/go-yit"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"golang.org/x/exp/slices"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v3"
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
		RecurseSubmodules: git.NoRecurseSubmodules,
		Depth:             1,
		Auth:              wgit.GetGitAuth(),
	}

	log.Printf("cloning sources from %s tag %s into a temporary directory '%s', this may take a while", repoValue, dir, evaluatedTag)

	maxRetries := 3
	r := &git.Repository{}
	for attempt := 0; attempt < maxRetries; attempt++ {
		r, err = git.PlainClone(dir, false, cloneOpts)
		if err == nil {
			break
		}
		log.Printf("Attempt %d failed to clone %s ref %s with error: %v", attempt+1, repoValue, evaluatedTag, err)
		if attempt < maxRetries-1 {
			log.Println("Retrying...")
			time.Sleep(time.Second * 2)
			// delete the temporary directory
			err = os.RemoveAll(dir)
			if err != nil {
				return fmt.Errorf("failed to remove temporary directory %s: %w", dir, err)
			}
			// recreate the directory
			err = os.MkdirAll(dir, 0o755)

			if err != nil {
				return fmt.Errorf("failed to remove temporary directory %s: %w", dir, err)
			}
			if err != nil {
				return fmt.Errorf("failed to remove temporary directory %s: %w", dir, err)
			}
		} else {
			return fmt.Errorf("failed to clone %s ref %s after %d attempts", repoValue, evaluatedTag, maxRetries)
		}
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
	if p.With["replaces"] != "" {
		replaces = strings.Split(p.With["replaces"], " ")
	}
	pkgReplaceVersions := map[string]string{}
	for _, pkg := range replaces {
		replacePkg := strings.Split(pkg, "=")
		parts := strings.Split(replacePkg[1], "@")
		pkgReplaceVersions[parts[0]] = parts[1]
	}

	if p.With["deps"] != "" {
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
					updateDependencyLists(replace.New.Path, replace.New.Version, pkgRequireVersions, &deps, "{pkg}={pkg}@{ver}")
				}
			}
			if _, ok := pkgReplaceVersions[replace.New.Path]; ok {
				if semver.IsValid(pkgReplaceVersions[replace.New.Path]) {
					// If the replace block in the upstream go.mod contains a newer version then remove the existing dep from replaces
					updateDependencyLists(replace.New.Path, replace.New.Version, pkgReplaceVersions, &replaces, "{pkg}={pkg}@{ver}")
				}
			}
		}
	}
	// Detect if the list of packages contain any require statement for the package
	for _, require := range modFile.Require {
		if require != nil {
			if _, ok := pkgRequireVersions[require.Mod.Path]; ok {
				if semver.IsValid(pkgRequireVersions[require.Mod.Path]) {
					updateDependencyLists(require.Mod.Path, require.Mod.Version, pkgRequireVersions, &deps, "{pkg}@{ver}")
				}
			}
			if _, ok := pkgReplaceVersions[require.Mod.Path]; ok {
				if semver.IsValid(pkgReplaceVersions[require.Mod.Path]) {
					// If the require block in the upstream go.mod contains a newer version then remove the existing dep from replaces
					updateDependencyLists(require.Mod.Path, require.Mod.Version, pkgReplaceVersions, &replaces, "{pkg}={pkg}@{ver}")
				}
			}
		}
	}

	if p.With["deps"] != "" {
		p.With["deps"] = strings.TrimSpace(strings.Join(deps, " "))
	}

	if p.With["replaces"] != "" {
		p.With["replaces"] = strings.TrimSpace(strings.Join(replaces, " "))
	}

	log.Printf("New [deps]: %v\n", p.With["deps"])
	log.Printf("New [replaces]: %v\n", p.With["replaces"])

	return nil
}

// optionally remove the package from the list if the version is greater or equal to the target version
func updateDependencyLists(pkgPath, version string, versionsMap map[string]string, list *[]string, format string) {
	if targetVersion, ok := versionsMap[pkgPath]; ok && semver.IsValid(targetVersion) {
		// Determine comparison based on the presence of "=" in the format, which indicates a replacement.
		isReplace := strings.Contains(format, "=")
		compareResult := semver.Compare(version, targetVersion)

		// For requires, we check for >= 0; for replaces, > 0.
		if (!isReplace && compareResult >= 0) || (isReplace && compareResult > 0) {
			formattedString := strings.ReplaceAll(format, "{pkg}", pkgPath)
			formattedString = strings.ReplaceAll(formattedString, "{ver}", targetVersion)
			idx := slices.Index(*list, formattedString)
			if idx != -1 {
				*list = append((*list)[:idx], (*list)[idx+1:]...)
				delete(versionsMap, pkgPath)
			}
		}
	}
}

// ContainsGoBumpPipeline checks whether there is a gobump in the wolfi package definition.
// If so, we will attempt to clean the unnecessary dependencies.
func ContainsGoBumpPipeline(updated *config.Configuration) bool {
	for i := range updated.Pipeline {
		if updated.Pipeline[i].Uses == "go/bump" {
			return true
		}
	}
	return false
}

func CleanupGoBumpDeps(doc *yaml.Node, updated *config.Configuration, tidy bool, mutations map[string]string) error {
	tempDir, err := os.MkdirTemp("", "wolfibump")
	if err != nil {
		return fmt.Errorf("failed to create temporary folder to clone package configs into: %w", err)
	}
	defer os.RemoveAll(tempDir)

	pipelineNode := findPipelineNode(doc)
	if pipelineNode == nil {
		return fmt.Errorf("pipeline node not found in the Wolfi definition")
	}

	checkedOut := false
	i := 0
	for i < len(updated.Pipeline) {
		// TODO(hectorj2f): add support for fetch pipelines
		if updated.Pipeline[i].Uses == "git-checkout" {
			destinationDir := tempDir
			dest := updated.Pipeline[i].With["destination"]
			if dest != "" {
				destinationDir = path.Join(tempDir, dest)
			}
			err := gitCheckout(&updated.Pipeline[i], destinationDir, mutations)
			if err != nil {
				return fmt.Errorf("failed to git checkout the repository: %v", err)
			}
			checkedOut = true
		}
		if checkedOut && updated.Pipeline[i].Uses == "go/bump" {
			log.Printf("checking the pipeline: %v", updated.Pipeline[i])

			// get the go/bump pipeline
			if err := cleanupGoBumpPipelineDeps(&updated.Pipeline[i], tempDir, tidy); err != nil {
				return err
			}
			if updated.Pipeline[i].With["deps"] == "" && updated.Pipeline[i].With["replaces"] == "" {
				updated.Pipeline = slices.Delete(updated.Pipeline, i, (i + 1))
				// Remove node from the yaml root node
				if err := removeNodeAtIndex(pipelineNode, i); err != nil {
					return err
				}
				// deleted element in the pipeline array
				continue
			}
			if err := updateGoBumpStep(pipelineNode.Content[i], &updated.Pipeline[i]); err != nil {
				return err
			}
		}
		// Increase the position in array of pipelines
		i++
	}

	return nil
}

// findPipelineNode finds the pipeline node in the YAML document
func findPipelineNode(doc *yaml.Node) *yaml.Node {
	it := yit.FromNode(doc).RecurseNodes()
	// Search for the pipeline node
	for node, ok := it(); ok; node, ok = it() {
		if node.Kind == yaml.MappingNode {
			// Search for the pipeline node
			for i := 0; i < len(node.Content); i += 2 {
				if node.Content[i].Value == "pipeline" {
					return node.Content[i+1]
				}
			}
		}
	}
	return nil
}

// removeNodeAtIndex removes a node from a sequence node at the specified index
func removeNodeAtIndex(parentNode *yaml.Node, index int) error {
	if parentNode.Kind != yaml.SequenceNode {
		return fmt.Errorf("parentNode %v is not a SequenceNode", parentNode.Kind)
	}

	// Check if index is within the range of the slice
	if index < 0 || index >= len(parentNode.Content) {
		return fmt.Errorf("index out of range: %d", index)
	}

	// Remove the node at the specified index
	parentNode.Content = append(parentNode.Content[:index], parentNode.Content[index+1:]...)
	return nil
}

func updateGoBumpStep(stepNode *yaml.Node, p *config.Pipeline) error {
	updated := false
	for i := 0; i < len(stepNode.Content); i += 2 {
		if stepNode.Content[i].Value == "with" {
			withNode := stepNode.Content[i+1]
			for j := 0; j < len(withNode.Content); j += 2 {
				if withNode.Content[j].Value == "deps" {
					if p.With["deps"] == "" {
						withNode.Content = slices.Delete(withNode.Content, j, (j + 2))
						updated = true
					} else {
						depsNode := withNode.Content[j+1]
						if depsNode.Kind != yaml.ScalarNode {
							return fmt.Errorf("deps field is not a scalar")
						}
						depsNode.Value = p.With["deps"]
						updated = true
					}
				}
				if withNode.Content[j].Value == "replaces" {
					if p.With["replaces"] == "" {
						withNode.Content = slices.Delete(withNode.Content, j, (j + 2))
						updated = true
					} else {
						replacesNode := withNode.Content[j+1]
						if replacesNode.Kind != yaml.ScalarNode {
							return fmt.Errorf("replaces field is not a scalar")
						}
						replacesNode.Value = p.With["replaces"]
						updated = true
					}
				}

				if p.With["modroot"] != "" && withNode.Content[j].Value == "modroot" {
					modrootNode := withNode.Content[j+1]
					if modrootNode.Kind != yaml.ScalarNode {
						return fmt.Errorf("modroot field is not a scalar")
					}
					modrootNode.Value = p.With["modroot"]
					updated = true
				}
			}
		}
	}
	if !updated {
		return fmt.Errorf("go/bump step deps or replaces field not found")
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
