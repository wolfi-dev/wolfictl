package checks

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/dprotaso/go-yit"

	version "github.com/wolfi-dev/wolfictl/pkg/versions"

	"github.com/fatih/color"

	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/util"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pkg/errors"
	"github.com/wolfi-dev/wolfictl/pkg/lint"
	"github.com/wolfi-dev/wolfictl/pkg/melange"
	"github.com/wolfi-dev/wolfictl/pkg/update"
	"gopkg.in/yaml.v3"
)

type CheckUpdateOptions struct {
	Dir             string
	OverrideVersion string
	Logger          *log.Logger
}

// SetupUpdate will create the options needed to call wolfictl update functions
func SetupUpdate() (*update.Options, lint.EvalRuleErrors) {
	o := update.New()
	o.GithubReleaseQuery = true
	o.ReleaseMonitoringQuery = true
	o.ErrorMessages = make(map[string]string)
	o.Logger = log.New(log.Writer(), "wolfictl check update: ", log.LstdFlags|log.Lmsgprefix)
	checkErrors := make(lint.EvalRuleErrors, 0)

	return &o, checkErrors
}

// CheckUpdates will use the melange update config to get the latest versions and validate fetch and git-checkout pipelines
func (o CheckUpdateOptions) CheckUpdates(ctx context.Context, files []string) error {
	updateOpts, checkErrors := SetupUpdate()

	changedPackages := GetPackagesToUpdate(files)

	validateUpdateConfig(changedPackages, &checkErrors)

	latestVersions, err := updateOpts.GetLatestVersions(o.Dir, changedPackages)
	if err != nil {
		addCheckError(&checkErrors, err)
	}

	handleErrorMessages(updateOpts, &checkErrors)

	if o.OverrideVersion == "" {
		o.checkForLatestVersions(latestVersions, &checkErrors)
	}

	if len(checkErrors) == 0 {
		err := o.processUpdates(ctx, latestVersions, &checkErrors)
		if err != nil {
			addCheckError(&checkErrors, err)
		}
	}

	return checkErrors.WrapErrors()
}

// validates update configuration
func validateUpdateConfig(files []string, checkErrors *lint.EvalRuleErrors) {
	for _, file := range files {
		// skip hidden files
		if strings.HasPrefix(file, ".") {
			continue
		}

		// first need to read raw bytes as unmarshalling a struct without a pointer means update will never be nil
		if !strings.HasSuffix(file, ".yaml") {
			file += ".yaml"
		}
		yamlData, err := os.ReadFile(file)
		if err != nil {
			addCheckError(checkErrors, errors.Wrapf(err, "failed to read %s", file))
			continue
		}

		var node yaml.Node
		err = yaml.Unmarshal(yamlData, &node)
		if err != nil {
			addCheckError(checkErrors, errors.Wrapf(err, "failed to unmarshal %s", file))
			continue
		}

		if node.Content == nil {
			addCheckError(checkErrors, fmt.Errorf("config %s has no yaml content", file))
			continue
		}
		// loop over content to ensure an update key exists
		err = containsKey(node.Content[0], "update")
		if err != nil {
			addCheckError(checkErrors, fmt.Errorf("config %s does not have update config provided, see examples in this repository.  Or use update.enabled=false, be aware maintainers may require enabled=true so the package does not become stale", file))
			continue
		}

		// now make sure update config is configured
		c, err := build.ParseConfiguration(file)
		if err != nil {
			addCheckError(checkErrors, errors.Wrapf(err, "failed to parse %s", file))
			continue
		}

		// ensure a backend has been configured
		if c.Update.Enabled {
			if c.Update.ReleaseMonitor == nil && c.Update.GitHubMonitor == nil {
				addCheckError(checkErrors, fmt.Errorf("config %s has update config enabled but no release-monitor or github backend monitor configured, see examples in this repository", file))
				continue
			}
		}
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

func GetPackagesToUpdate(files []string) []string {
	packagesToUpdate := []string{}
	for _, f := range files {
		packagesToUpdate = append(packagesToUpdate, strings.TrimSuffix(f, ".yaml"))
	}

	return packagesToUpdate
}

func addCheckError(checkErrors *lint.EvalRuleErrors, err error) {
	*checkErrors = append(*checkErrors, lint.EvalRuleError{
		Error: fmt.Errorf(err.Error()),
	})
}

func handleErrorMessages(updateOpts *update.Options, checkErrors *lint.EvalRuleErrors) {
	for _, message := range updateOpts.ErrorMessages {
		addCheckError(checkErrors, errors.New(message))
	}
}

// check if the current package.version is the latest according to the update config
func (o CheckUpdateOptions) checkForLatestVersions(latestVersions map[string]update.NewVersionResults, checkErrors *lint.EvalRuleErrors) {
	for k, v := range latestVersions {
		c, err := build.ParseConfiguration(filepath.Join(o.Dir, k+".yaml"))
		if err != nil {
			addCheckError(checkErrors, err)
			continue
		}
		currentVersion, err := version.NewVersion(c.Package.Version)
		if err != nil {
			addCheckError(checkErrors, err)
			continue
		}

		latestVersion, err := version.NewVersion(v.Version)
		if err != nil {
			addCheckError(checkErrors, err)
			continue
		}
		if currentVersion.LessThan(latestVersion) {
			addCheckError(checkErrors, fmt.Errorf("package %s: update found newer version %s compared with package.version %s in melange config", k, v.Version, c.Package.Version))
		}
	}
}

// iterate over slice of packages, optionally override the package.version and verify fetch + git-checkout work with latest versions
func (o CheckUpdateOptions) processUpdates(ctx context.Context, latestVersions map[string]update.NewVersionResults, checkErrors *lint.EvalRuleErrors) error {
	tempDir, err := os.MkdirTemp("", "wolfictl")
	if err != nil {
		return err
	}

	defer os.RemoveAll(tempDir)

	for packageName, newVersion := range latestVersions {
		srcConfigFile := filepath.Join(o.Dir, packageName+".yaml")

		dryRunConfig, err := build.ParseConfiguration(srcConfigFile)
		if err != nil {
			return err
		}
		applyOverrides(&o, dryRunConfig)

		data, err := yaml.Marshal(dryRunConfig)
		if err != nil {
			return err
		}

		tmpConfigFile := filepath.Join(tempDir, packageName+".yaml")
		err = os.WriteFile(tmpConfigFile, data, os.FileMode(0o644))
		if err != nil {
			return err
		}

		// melange bump will modify the modified copy of the melange config
		err = melange.Bump(ctx, tmpConfigFile, newVersion.Version, newVersion.Commit)
		if err != nil {
			addCheckError(checkErrors, errors.Wrapf(err, "package %s: failed to validate update config, melange bump", packageName))
			continue
		}

		updated, err := build.ParseConfiguration(tmpConfigFile)
		if err != nil {
			return err
		}

		pctx := &build.PipelineBuild{
			Build: &build.Build{
				Configuration: *updated,
			},
			Package: &updated.Package,
		}

		// get a map of variable mutations we can substitute vars in URLs
		mutations, err := build.MutateWith(pctx, map[string]string{})
		if err != nil {
			return err
		}

		// if manual update is expected then let's not try to validate pipelines
		if updated.Update.Manual {
			o.Logger.Println("manual update configured, skipping pipeline validation")
			continue
		}

		// download or git clone sources into a temp folder to validate the update config
		verifyPipelines(ctx, o, updated, mutations, checkErrors)
	}
	return nil
}

func applyOverrides(options *CheckUpdateOptions, dryRunConfig *build.Configuration) {
	if options.OverrideVersion != "" {
		dryRunConfig.Package.Version = options.OverrideVersion
	}
}

func verifyPipelines(ctx context.Context, o CheckUpdateOptions, updated *build.Configuration, mutations map[string]string, checkErrors *lint.EvalRuleErrors) {
	for i := range updated.Pipeline {
		var err error
		pipeline := updated.Pipeline[i]

		if pipeline.Uses == "fetch" {
			err = o.verifyFetch(ctx, &pipeline, mutations)
		}
		if pipeline.Uses == "git-checkout" {
			err = o.verifyGitCheckout(&pipeline, mutations)
		}
		if err != nil {
			addCheckError(checkErrors, err)
		}
	}
}

func (o CheckUpdateOptions) verifyFetch(ctx context.Context, p *build.Pipeline, m map[string]string) error {
	uriValue := p.With["uri"]
	if uriValue == "" {
		return fmt.Errorf("no uri to fetch")
	}

	// evaluate var substitutions
	evaluatedURI, err := build.MutateStringFromMap(m, uriValue)
	if err != nil {
		return err
	}

	o.Logger.Printf("downloading sources from %s into a temporary directory, this may take a while", evaluatedURI)

	filename, err := util.DownloadFile(ctx, evaluatedURI)
	if err != nil {
		return errors.Wrapf(err, "failed to verify fetch %s", evaluatedURI)
	}

	o.Logger.Println(color.GreenString("fetch was successful"))

	return os.RemoveAll(filename)
}

func (o CheckUpdateOptions) verifyGitCheckout(p *build.Pipeline, m map[string]string) error {
	repoValue := p.With["repository"]
	if repoValue == "" {
		return fmt.Errorf("no repository to checkout")
	}

	tagValue := p.With["tag"]
	if tagValue == "" {
		return fmt.Errorf("no tag to checkout")
	}

	// evaluate var substitutions
	evaluatedTag, err := build.MutateStringFromMap(m, tagValue)
	if err != nil {
		return err
	}

	tempDir, err := os.MkdirTemp("", "wolfictl")
	if err != nil {
		return err
	}

	cloneOpts := &git.CloneOptions{
		URL:               repoValue,
		ReferenceName:     plumbing.ReferenceName(fmt.Sprintf("refs/tags/%s", evaluatedTag)),
		Progress:          os.Stdout,
		RecurseSubmodules: git.NoRecurseSubmodules,
		RemoteName:        "origin",
		Depth:             1,
		NoCheckout:        true,
	}

	o.Logger.Printf("cloning sources from %s tag %s into a temporary directory, this may take a while", repoValue, evaluatedTag)

	r, err := git.PlainClone(tempDir, false, cloneOpts)
	if err != nil {
		return errors.Wrapf(err, "failed to clone %s ref %s", repoValue, evaluatedTag)
	}
	if r == nil {
		return fmt.Errorf("clone is empty %s ref %s", repoValue, evaluatedTag)
	}
	o.Logger.Println(color.GreenString("git-checkout was successful"))

	return os.RemoveAll(tempDir)
}
