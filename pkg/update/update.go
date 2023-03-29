package update

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/go-github/v50/github"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/shurcooL/githubv4"
	"golang.org/x/exp/maps"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"

	"github.com/wolfi-dev/wolfictl/pkg/gh"
	wgit "github.com/wolfi-dev/wolfictl/pkg/git"
	"github.com/wolfi-dev/wolfictl/pkg/git/submodules"
	http2 "github.com/wolfi-dev/wolfictl/pkg/http"
	"github.com/wolfi-dev/wolfictl/pkg/melange"
)

type Options struct {
	PackageNames           []string
	PackageConfigs         map[string]melange.Packages
	PullRequestBaseBranch  string
	PullRequestTitle       string
	RepoURI                string
	DefaultBranch          string
	Batch                  bool
	DryRun                 bool
	ReleaseMonitoringQuery bool
	GithubReleaseQuery     bool
	UseGitSign             bool
	Client                 *http2.RLHTTPClient
	Logger                 *log.Logger
	GitHubHTTPClient       *http2.RLHTTPClient
	GitGraphQLClient       *githubv4.Client
}

const (
	secondsToSleepWhenRateLimited = 30
	maxPullRequestRetries         = 10
	wolfiImage                    = `
<p align="center">
  <img src="https://raw.githubusercontent.com/wolfi-dev/.github/b535a42419ce0edb3c144c0edcff55a62b8ec1f8/profile/wolfi-logo-light-mode.svg" />
</p>
`
)

// New initialise including a map of existing wolfios packages
func New() Options {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)

	options := Options{
		Client: &http2.RLHTTPClient{
			Client: http.DefaultClient,

			// 1 request every (n) second(s) to avoid DOS'ing server
			Ratelimiter: rate.NewLimiter(rate.Every(3*time.Second), 1),
		},
		GitHubHTTPClient: &http2.RLHTTPClient{
			Client: oauth2.NewClient(context.Background(), ts),

			// 1 request every (n) second(s) to avoid DOS'ing server. https://docs.github.com/en/rest/guides/best-practices-for-integrators?apiVersion=2022-11-28#dealing-with-secondary-rate-limits
			Ratelimiter: rate.NewLimiter(rate.Every(3*time.Second), 1),
		},
		GitGraphQLClient: githubv4.NewClient(oauth2.NewClient(context.Background(), ts)),
		Logger:           log.New(log.Writer(), "wolfictl update: ", log.LstdFlags|log.Lmsgprefix),
		DefaultBranch:    "main",
	}

	return options
}

func (o *Options) Update() error {
	// keep a slice of messages to print at the end of the update to help users diagnose non-fatal problems
	errorMessages := make(map[string]string)
	packagesToUpdate := make(map[string]string)

	// clone the melange config git repo into a temp folder so we can work with it
	tempDir, err := os.MkdirTemp("", "wolfictl")
	if err != nil {
		return fmt.Errorf("failed to create temporary folder to clone package configs into: %w", err)
	}
	if o.DryRun {
		o.Logger.Printf("using working directory %s", tempDir)
	} else {
		defer os.Remove(tempDir)
	}

	cloneOpts := &git.CloneOptions{
		URL:               o.RepoURI,
		Progress:          os.Stdout,
		RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
		Auth:              wgit.GetGitAuth(),
		Depth:             1,
	}

	repo, err := git.PlainClone(tempDir, false, cloneOpts)
	if err != nil {
		return fmt.Errorf("failed to clone repository %s into %s: %w", o.RepoURI, tempDir, err)
	}

	packagesToUpdate, err = o.GetNewVersions(tempDir, o.PackageNames, errorMessages)
	if err != nil {
		return errors.Wrapf(err, "failed to get package updates")
	}

	// update melange configs in our cloned git repository with any new package versions
	err = o.updatePackagesGitRepository(repo, packagesToUpdate, errorMessages)
	if err != nil {
		return fmt.Errorf("failed to update packages in git repository: %w", err)
	}

	// certain errors should not halt the updates, print them at the end
	for k, message := range errorMessages {
		o.Logger.Printf("%s: %s\n", k, color.YellowString(message))
	}

	return nil
}

func (o *Options) GetNewVersions(dir string, packageNames []string, errorMessages map[string]string) (map[string]string, error) {
	var err error
	latestVersions := make(map[string]string)

	// first, let's get the melange package(s) from the target git repo, that we want to check for updates
	o.PackageConfigs, err = melange.ReadPackageConfigs(packageNames, dir)
	if err != nil {
		return nil, fmt.Errorf("failed to get package configs: %w", err)
	}

	// remove any updates that have been disabled
	for i := range o.PackageConfigs {
		c := o.PackageConfigs[i]
		if !c.Config.Update.Enabled {
			delete(o.PackageConfigs, i)
		}
	}

	if o.GithubReleaseQuery {
		// let's get any versions that use GITHUB first as we can do that using reduced graphql requests
		g := NewGitHubReleaseOptions(o.PackageConfigs, o.GitGraphQLClient, o.GitHubHTTPClient)
		v, err := g.getLatestGitHubVersions(errorMessages)
		if err != nil {
			return latestVersions, fmt.Errorf("failed getting github releases: %w", err)
		}

		maps.Copy(latestVersions, v)
	}

	if o.ReleaseMonitoringQuery {
		// get latest versions from https://release-monitoring.org/
		m := MonitorService{
			Client:           o.Client,
			GitHubHTTPClient: o.GitHubHTTPClient,
			Logger:           o.Logger,
		}
		v, err := m.getLatestReleaseMonitorVersions(o.PackageConfigs, errorMessages)
		if err != nil {
			return nil, fmt.Errorf("failed release monitor versions: %w", err)
		}
		maps.Copy(latestVersions, v)
	}
	return latestVersions, nil
}

// function will iterate over all packages that need to be updated and create a pull request for each change by default unless batch mode which creates a single pull request
func (o *Options) updatePackagesGitRepository(repo *git.Repository, packagesToUpdate map[string]string, errorMessages map[string]string) error {
	// bump packages that need updating
	for packageName, latestVersion := range packagesToUpdate {
		// let's work on a branch when updating package versions, so we can create a PR from that branch later
		ref, err := o.switchBranch(repo)
		if err != nil {
			return fmt.Errorf("failed to switch to working git branch: %w", err)
		}

		errorMessage, err := o.updateGitPackage(repo, packageName, latestVersion, ref)
		if err != nil {
			return err
		}
		if errorMessage != "" {
			errorMessages[packageName] = errorMessage
		}
	}

	return nil
}

func (o *Options) updateGitPackage(repo *git.Repository, packageName, latestVersion string, ref plumbing.ReferenceName) (string, error) {
	// get the filename from the map of melange configs we loaded at the start
	config, ok := o.PackageConfigs[packageName]
	if !ok {
		return "", fmt.Errorf("no melange config found for package %s", packageName)
	}

	configFile := filepath.Join(config.Dir, config.Filename)
	if configFile == "" {
		return "", fmt.Errorf("no config filename found for package %s", packageName)
	}

	// if new versions are available lets bump the packages in the target melange git repo
	err := melange.Bump(configFile, latestVersion)
	if err != nil {
		// add this to the list of messages to print at the end of the update
		return fmt.Sprintf("failed to bump config file %s to version %s: %s", configFile, latestVersion, err.Error()), nil
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("failed to get git worktree: %w", err)
	}

	// this needs to be the relative path set when reading the files initially
	_, err = worktree.Add(config.Filename)
	if err != nil {
		return "", fmt.Errorf("failed to git add %s: %w", configFile, err)
	}

	// for now wolfi is using a Makefile, if it exists check if the package is listed and update the version + epoch if it is
	err = o.updateMakefile(config.Dir, packageName, latestVersion, worktree)
	if err != nil {
		return fmt.Sprintf("failed to update Makefile: %s", err.Error()), nil
	}

	// if mapping data has a strip prefix, add it back in to the version for when updating git modules
	latestVersionWithPrefix := latestVersion
	ghm := o.PackageConfigs[packageName].Config.Update.GitHubMonitor
	if ghm != nil {
		if ghm.StripPrefix != "" {
			latestVersionWithPrefix = ghm.StripPrefix + latestVersionWithPrefix
		}
	}
	// some repos could use git submodules, let's check if a submodule file exists and bump any matching packages
	err = o.updateGitModules(config.Dir, packageName, latestVersionWithPrefix, worktree)
	if err != nil {
		return fmt.Sprintf("failed to update git modules: %s", err.Error()), nil
	}

	// if we're not running in batch mode, lets commit and PR each change
	if !o.DryRun {
		pr, err := o.proposeChanges(repo, ref, packageName, latestVersion)
		if err != nil {
			return fmt.Sprintf("failed to propose changes: %s", err.Error()), nil
		}
		o.Logger.Println(color.GreenString(pr))
	}
	return "", nil
}

// this feels very hacky but the Makefile is going away with help from Dag so plan to delete this func soon
// for now wolfi is using a Makefile, if it exists check if the package is listed and update the version + epoch if it is
func (o *Options) updateMakefile(tempDir, packageName, latestVersion string, worktree *git.Worktree) error {
	file, err := os.Open(filepath.Join(tempDir, "Makefile"))
	if err != nil {
		// if the Makefile doesn't exist anymore let's just return
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var newFile []byte

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, fmt.Sprintf("$(eval $(call build-package,%s,", packageName)) {
			line = fmt.Sprintf("$(eval $(call build-package,%s,%s-r%s))", packageName, latestVersion, "0")
		}
		newFile = append(newFile, []byte(line+"\n")...)
	}

	info, err := os.Stat(filepath.Join(tempDir, "Makefile"))
	if err != nil {
		return fmt.Errorf("failed to check file permissions of the Makefile: %w", err)
	}

	if err := os.WriteFile(filepath.Join(tempDir, "Makefile"), newFile, info.Mode()); err != nil {
		return fmt.Errorf("failed to write Makefile: %w", err)
	}

	if _, err = worktree.Add("Makefile"); err != nil {
		return fmt.Errorf("failed to git add Makefile: %w", err)
	}
	return nil
}

// some melange config repos use submodules to pull in git repositories into the source dir before the melange pipelines run
// this function is a noop if no git submodules exist
func (o *Options) updateGitModules(dir, packageName, version string, wt *git.Worktree) error {
	// if no gitmodules file exist this in a noop
	if _, err := os.Stat(filepath.Join(dir, ".gitmodules")); errors.Is(err, os.ErrNotExist) {
		return nil
	}

	ghm := o.PackageConfigs[packageName].Config.Update.GitHubMonitor

	if ghm == nil {
		o.Logger.Printf("package %s  is not a github repo in mapping data, not attempting to bump gitmodules", packageName)
		return nil
	}

	if ghm.Identifier == "" {
		o.Logger.Printf("no identifier found in mapping data for package %s, not attempting to bump gitmodules", packageName)
		return nil
	}

	parts := strings.Split(ghm.Identifier, "/")
	if len(parts) != 2 {
		o.Logger.Printf("identifier doesn't look like a github owner/repo in mapping data for package %s, not attempting to bump gitmodules", packageName)
		return nil
	}

	return submodules.Update(dir, parts[0], parts[1], version, wt)
}

// create a unique branch
func (o *Options) switchBranch(repo *git.Repository) (plumbing.ReferenceName, error) {
	name := uuid.New().String()

	worktree, err := repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("failed to get git worktree: %w", err)
	}

	// make sure we are on the main branch to start with
	ref := plumbing.ReferenceName(fmt.Sprintf("refs/heads/" + o.DefaultBranch))

	err = worktree.Checkout(&git.CheckoutOptions{
		Create: false,
		Branch: ref,
	})
	if err != nil {
		return "", fmt.Errorf("failed to checkout ref %s: %w", ref, err)
	}

	// create a unique branch to work from
	ref = plumbing.ReferenceName(fmt.Sprintf("refs/heads/wolfictl-%v", name))
	err = worktree.Checkout(&git.CheckoutOptions{
		Create: true,
		Branch: ref,
	})

	if err != nil {
		return "", fmt.Errorf("failed to checkout to temporary branch: %w", err)
	}

	return ref, err
}

// commits package update changes and creates a pull request
func (o *Options) proposeChanges(repo *git.Repository, ref plumbing.ReferenceName, packageName, newVersion string) (string, error) {
	gitURL, err := wgit.GetRemoteURL(repo)
	if err != nil {
		return "", fmt.Errorf("failed to find git origin URL: %w", err)
	}

	basePullRequest := gh.BasePullRequest{
		RepoName:              gitURL.Name,
		Owner:                 gitURL.Organisation,
		Branch:                ref.String(),
		PullRequestBaseBranch: o.PullRequestBaseBranch,
		Retries:               0,
	}

	client := github.NewClient(o.GitHubHTTPClient.Client)
	gitOpts := gh.GitOptions{
		GithubClient:                  client,
		MaxPullRequestRetries:         maxPullRequestRetries,
		SecondsToSleepWhenRateLimited: secondsToSleepWhenRateLimited,
		Logger:                        o.Logger,
	}

	getPr := &gh.GetPullRequest{
		BasePullRequest: basePullRequest,
		PackageName:     packageName,
		Version:         newVersion,
	}

	// if an existing PR is open with the same version skip, if it's an older version close the PR and we'll create a new one
	exitingPR, err := gitOpts.CheckExistingPullRequests(getPr)
	if err != nil {
		return "", fmt.Errorf("failed to check for existing pull requests: %w", err)
	}

	if exitingPR != "" {
		o.Logger.Printf(
			"found matching open pull request for %s/%s %s",
			packageName, newVersion, exitingPR,
		)
		return "", nil
	}

	// commit the changes
	if err = o.commitChanges(repo, packageName, newVersion); err != nil {
		return "", fmt.Errorf("failed to commit changes: %w", err)
	}

	// setup githubReleases auth using standard environment variables
	pushOpts := &git.PushOptions{
		RemoteName: "origin",
		Auth:       wgit.GetGitAuth(),
	}

	// push the version update changes to our working branch
	if err := repo.Push(pushOpts); err != nil {
		if err.Error() == "authorization failed" {
			return "", errors.Wrapf(err, "failed to auth with git provider, does your personal access token have the repo scope? https://github.com/settings/tokens/new?scopes=repo")
		}
		return "", fmt.Errorf("failed to git push: %w", err)
	}

	// now let's create a pull request

	// if we have a single version use it in the PR title, this might be a batch with multiple versions so default to a simple title
	var title string
	if newVersion != "" {
		title = fmt.Sprintf(o.PullRequestTitle, packageName, newVersion)
	} else {
		title = fmt.Sprintf(o.PullRequestTitle, packageName, "new versions")
	}

	// Create an NewPullRequest struct which is used to create the real pull request from
	newPR := &gh.NewPullRequest{
		BasePullRequest: basePullRequest,
		Title:           title,
		Body:            wolfiImage,
	}

	// create the pull request
	prLink, err := gitOpts.OpenPullRequest(newPR)
	if err != nil {
		return "", fmt.Errorf("failed to create pull request: %w", err)
	}

	return prLink, nil
}

// commit changes to git
func (o *Options) commitChanges(repo *git.Repository, packageName, latestVersion string) error {
	worktree, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get git worktree: %w", err)
	}

	commitMessage := ""
	if latestVersion != "" {
		commitMessage = fmt.Sprintf("%s/%s package update", packageName, latestVersion)
	} else {
		commitMessage = "Updating wolfi packages"
	}
	commitOpts := &git.CommitOptions{}
	commitOpts.Author = wgit.GetGitAuthorSignature()

	if o.UseGitSign {
		err := wgit.SetGitSignOptions(worktree.Filesystem.Root())
		if err != nil {
			return fmt.Errorf("failed to set git config: %w", err)
		}

		// maybe we change this when https://github.com/go-git/go-git/issues/400 is implemented
		cmd := exec.Command("git", "commit", "-sm", commitMessage)
		cmd.Dir = worktree.Filesystem.Root()
		rs, err := cmd.Output()
		if err != nil {
			return errors.Wrapf(err, "failed to git sign commit %s", rs)
		}
	} else {
		if _, err = worktree.Commit(commitMessage, commitOpts); err != nil {
			return fmt.Errorf("failed to git commit: %w", err)
		}
	}

	return nil
}
