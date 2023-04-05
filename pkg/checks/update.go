package checks

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

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
func (o CheckUpdateOptions) CheckUpdates(files []string) error {
	updateOpts, checkErrors := SetupUpdate()

	latestVersions, err := updateOpts.GetLatestVersions(o.Dir, GetPackagesToUpdate(files))
	if err != nil {
		addCheckError(&checkErrors, err)
	}

	handleErrorMessages(updateOpts, &checkErrors)

	if o.OverrideVersion == "" {
		o.checkForLatestVersions(latestVersions, &checkErrors)
	}

	if len(checkErrors) == 0 {
		err := o.processUpdates(latestVersions, &checkErrors)
		if err != nil {
			addCheckError(&checkErrors, err)
		}
	}

	return checkErrors.WrapErrors()
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
		}
		currentVersion, err := version.NewVersion(c.Package.Version)
		if err != nil {
			addCheckError(checkErrors, err)
		}

		latestVersion, err := version.NewVersion(v.Version)
		if err != nil {
			addCheckError(checkErrors, err)
		}
		if !currentVersion.Equal(latestVersion) {
			addCheckError(checkErrors, fmt.Errorf("package %s: update found newer version %s compared with package.version in melange config", k, v.Version))
		}
	}
}

// iterate over slice of packages, optionally override the package.version and verify fetch + git-checkout work with latest versions
func (o CheckUpdateOptions) processUpdates(latestVersions map[string]update.NewVersionResults, checkErrors *lint.EvalRuleErrors) error {
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
		err = melange.Bump(tmpConfigFile, newVersion.Version, newVersion.Commit)
		if err != nil {
			addCheckError(checkErrors, errors.Wrapf(err, "package %s: failed to validate update config, melange bump", packageName))
			continue
		}

		updated, err := build.ParseConfiguration(tmpConfigFile)
		if err != nil {
			return err
		}

		pctx := &build.PipelineContext{
			Context: &build.Context{
				Configuration: *updated,
			},
			Package: &updated.Package,
		}

		// get a map of variable mutations we can substitute vars in URLs
		mutations, err := build.MutateWith(pctx, map[string]string{})
		if err != nil {
			return err
		}

		// download or git clone sources into a temp folder to validate the update config
		verifyPipelines(o, updated, mutations, checkErrors)
	}
	return nil
}

func applyOverrides(options *CheckUpdateOptions, dryRunConfig *build.Configuration) {
	if options.OverrideVersion != "" {
		dryRunConfig.Package.Version = options.OverrideVersion
	}
}

func verifyPipelines(o CheckUpdateOptions, updated *build.Configuration, mutations map[string]string, checkErrors *lint.EvalRuleErrors) {
	for i := range updated.Pipeline {
		var err error
		pipeline := updated.Pipeline[i]

		if pipeline.Uses == "fetch" {
			err = o.verifyFetch(&pipeline, mutations)
		}
		if pipeline.Uses == "git-checkout" {
			err = o.verifyGitCheckout(&pipeline, mutations)
		}
		if err != nil {
			addCheckError(checkErrors, err)
		}
	}
}

func (o CheckUpdateOptions) verifyFetch(p *build.Pipeline, m map[string]string) error {
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

	filename, err := util.DownloadFile(evaluatedURI)
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
