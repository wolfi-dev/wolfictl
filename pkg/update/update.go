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
	"regexp"
	"strings"
	"time"

	"github.com/wolfi-dev/wolfictl/pkg/yam"

	melangebuild "chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/config"
	"github.com/fatih/color"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/go-github/v58/github"
	"github.com/google/uuid"
	"github.com/wolfi-dev/wolfictl/pkg/gh"
	wgit "github.com/wolfi-dev/wolfictl/pkg/git"
	http2 "github.com/wolfi-dev/wolfictl/pkg/http"
	"github.com/wolfi-dev/wolfictl/pkg/melange"
	"github.com/wolfi-dev/wolfictl/pkg/update/deps"
	wolfiversions "github.com/wolfi-dev/wolfictl/pkg/versions"
	"golang.org/x/exp/maps"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"
)

type Options struct {
	PackageNames           []string
	PackageConfigs         map[string]*melange.Packages
	PullRequestBaseBranch  string
	PullRequestTitle       string
	RepoURI                string
	DefaultBranch          string
	Batch                  bool
	DryRun                 bool
	ReleaseMonitoringQuery bool
	GithubReleaseQuery     bool
	UseGitSign             bool
	CreateIssues           bool
	ReleaseMonitorClient   *http2.RLHTTPClient
	Logger                 *log.Logger
	GitHubHTTPClient       *http2.RLHTTPClient
	ErrorMessages          map[string]string
	IssueLabels            []string
	MaxRetries             int
	PkgPath                string
	PackagesToUpdate       map[string]NewVersionResults
}

type NewVersionResults struct {
	Version                    string
	Commit                     string
	ReplaceExistingIssueNumber int
	ReplaceExistingPRNumber    int
	BumpEpoch                  bool
}

const (
	maxPullRequestRetries = 10
	bot                   = "wolfi-bot"
	wolfiImage            = `
<p align="center">
  <img src="https://raw.githubusercontent.com/wolfi-dev/.github/b535a42419ce0edb3c144c0edcff55a62b8ec1f8/profile/wolfi-logo-light-mode.svg" />
</p>
`
)

// New initialise including a map of existing wolfios packages
func New(ctx context.Context) Options {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)
	token := os.Getenv("RELEASE_MONITOR_TOKEN")

	var rateLimitDuration time.Duration
	if token == "" {
		rateLimitDuration = 5 * time.Second
	} else {
		rateLimitDuration = 1 * time.Second / 2
	}

	client := &http.Client{
		Transport: &CustomTransport{
			Transport: http.DefaultTransport,
			Token:     token,
		},
	}

	options := Options{
		ReleaseMonitorClient: &http2.RLHTTPClient{
			Client:      client,
			Ratelimiter: rate.NewLimiter(rate.Every(rateLimitDuration), 1),
		},

		GitHubHTTPClient: &http2.RLHTTPClient{
			Client: oauth2.NewClient(ctx, ts),

			// 1 request every (n) second(s) to avoid DOS'ing server. https://docs.github.com/en/rest/guides/best-practices-for-integrators?apiVersion=2022-11-28#dealing-with-secondary-rate-limits
			Ratelimiter: rate.NewLimiter(rate.Every(5*time.Second), 1),
		},
		Logger:        log.New(log.Writer(), "wolfictl update: ", log.LstdFlags|log.Lmsgprefix),
		DefaultBranch: "main",
		ErrorMessages: make(map[string]string),
	}
	return options
}

func (o *Options) Update(ctx context.Context) error {
	var err error
	var repo *git.Repository
	var latestVersions map[string]NewVersionResults

	// retry the whole process a few times in case of issues with the git repo
	for i := 0; i < o.MaxRetries; i++ {
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

		gitAuth, err := wgit.GetGitAuth(o.RepoURI)
		if err != nil {
			return fmt.Errorf("failed to get git auth: %w", err)
		}

		cloneOpts := &git.CloneOptions{
			URL:               o.RepoURI,
			Progress:          os.Stdout,
			RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
			ShallowSubmodules: true,
			Auth:              gitAuth,
			Depth:             1,
		}

		repo, err = git.PlainClone(tempDir, false, cloneOpts)
		if err != nil {
			return fmt.Errorf("failed to clone repository %s into %s: %w", o.RepoURI, tempDir, err)
		}

		// get the latest upstream versions available
		if latestVersions == nil {
			latestVersions, err = o.GetLatestVersions(ctx, tempDir, o.PackageNames)
			if err != nil {
				return fmt.Errorf("failed to get package updates: %w", err)
			}
		}

		// compare latest upstream versions with melange package versions and return a map of packages to update
		if o.PackagesToUpdate == nil {
			o.PackagesToUpdate, err = o.getPackagesToUpdate(latestVersions)
			if err != nil {
				return fmt.Errorf("failed to get package updates: %w", err)
			}

			// skip packages for which we already have an open issue or pull request
			err = o.removeExistingUpdates(ctx, repo)
			if err != nil {
				return fmt.Errorf("failed to get package updates: %w", err)
			}
		}

		// update melange configs in our cloned git repository with any new package versions
		err = o.updatePackagesGitRepository(ctx, repo)
		if err != nil {
			// we occasionally get errors when pushing to git and creating issues, so we should retry using a clean clone
			o.Logger.Printf("attempt %d: failed to update packages in git repository: %s", i+1, err)
			continue
		}

		// If we reach here, it means the task has been successful and we can break the loop
		break
	}

	// Check if an error still exists after the loop (i.e., all retry attempts failed)
	if err != nil {
		return fmt.Errorf("after %d attempts, failed to update packages in git repository: %w", o.MaxRetries, err)
	}

	// certain errors should not halt the updates, either create a GitHub Issue or print them
	for k, message := range o.ErrorMessages {
		// don't create an issue if we get an error about a missing git object
		// this happens intermittently and tends to recover on the next run
		// not able to reproduce locally, only seems to happen in GitHub Actions
		if strings.Contains(message, "failed to git push: object not found") {
			o.Logger.Printf("%s: %s\n", k, color.RedString(message))
			continue
		}
		if o.CreateIssues {
			issueURL, err := o.createErrorMessageIssue(ctx, repo, k, message)
			if err != nil {
				return err
			}
			o.Logger.Printf("%s: %s\n", k, color.YellowString(issueURL))
		} else {
			o.Logger.Printf("%s: %s\n", k, color.YellowString(message))
		}
	}

	return nil
}

func (o *Options) GetLatestVersions(ctx context.Context, dir string, packageNames []string) (map[string]NewVersionResults, error) {
	var err error
	latestVersions := make(map[string]NewVersionResults)

	// first, let's get the melange package(s) from the target git repo, that we want to check for updates
	o.PackageConfigs, err = melange.ReadPackageConfigs(ctx, packageNames, filepath.Join(dir, o.PkgPath))
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

	if len(o.PackageConfigs) == 0 {
		o.Logger.Printf("no package updates")
		return nil, nil
	}

	if o.GithubReleaseQuery {
		// let's get any versions that use GITHUB first as we can do that using reduced graphql requests
		g := NewGitHubReleaseOptions(o.PackageConfigs, o.GitHubHTTPClient)
		v, errorMessages, err := g.getLatestGitHubVersions()
		if err != nil {
			return latestVersions, fmt.Errorf("failed getting github releases: %w", err)
		}
		maps.Copy(o.ErrorMessages, errorMessages)
		maps.Copy(latestVersions, v)
	}

	if o.ReleaseMonitoringQuery {
		// get latest versions from https://release-monitoring.org/
		m := MonitorService{
			Client: o.ReleaseMonitorClient,
			Logger: o.Logger,
		}
		v, errorMessages := m.getLatestReleaseMonitorVersions(o.PackageConfigs)
		if err != nil {
			return nil, fmt.Errorf("failed release monitor versions: %w", err)
		}
		maps.Copy(o.ErrorMessages, errorMessages)
		maps.Copy(latestVersions, v)
	}

	return latestVersions, nil
}

// if provided, transform the version using the update config
func transformVersion(c config.Update, v string) (string, error) {
	if len(c.VersionTransform) == 0 {
		return v, nil
	}

	mutatedVersion := v

	for _, tf := range c.VersionTransform {
		matcher, err := regexp.Compile(tf.Match)
		if err != nil {
			return v, fmt.Errorf("unable to compile version transform regex: %w", err)
		}

		mutatedVersion = matcher.ReplaceAllString(mutatedVersion, tf.Replace)
	}

	return mutatedVersion, nil
}

// function will iterate over all packages that need to be updated and create a pull request for each change by default unless batch mode which creates a single pull request
func (o *Options) updatePackagesGitRepository(ctx context.Context, repo *git.Repository) error {
	// store the HEAD ref to switch back later
	headRef, err := repo.Head()
	if err != nil {
		return fmt.Errorf("failed to get the HEAD ref: %w", err)
	}

	// Bump packages that need updating
	for packageName, newVersion := range o.PackagesToUpdate {
		wt, err := repo.Worktree()
		if err != nil {
			return fmt.Errorf("failed to get the worktree: %w", err)
		}

		// Perform a hard reset to HEAD
		err = wt.Reset(&git.ResetOptions{Mode: git.HardReset})
		if err != nil {
			return fmt.Errorf("failed to reset git repo: %w", err)
		}

		// make sure we are on HEAD
		err = wt.Checkout(&git.CheckoutOptions{
			Branch: headRef.Name(),
		})
		if err != nil {
			return fmt.Errorf("failed to check out HEAD: %w", err)
		}

		// log the git status before we start to make sure we're in a clean state
		rs, err := debug(wt)
		if err != nil {
			return err
		}
		o.Logger.Printf("updatePackagesGitRepository: %s git status: %s", packageName, string(rs))

		// let's work on a branch when updating package versions, so we can create a PR from that branch later
		ref, err := o.createBranch(repo)
		if err != nil {
			return fmt.Errorf("failed to create git branch: %w", err)
		}

		errorMessage, err := o.updateGitPackage(ctx, repo, packageName, newVersion, ref)
		if err != nil {
			return err
		}
		if errorMessage != "" {
			// delete the package from the map so we don't try to update it again if we get a failure for another package and retry the whole process
			delete(o.PackagesToUpdate, packageName)
			o.ErrorMessages[packageName] = errorMessage
		}
	}

	return nil
}

func debug(wt *git.Worktree) ([]byte, error) {
	// add extra logging to help debug intermittent "object not found" when pushing
	cmd := exec.Command("git", "status")
	cmd.Dir = wt.Filesystem.Root()
	rs, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed run git status %s: %w", rs, err)
	}
	return rs, nil
}

func (o *Options) updateGitPackage(ctx context.Context, repo *git.Repository, packageName string, newVersion NewVersionResults, ref plumbing.ReferenceName) (string, error) {
	// get the filename from the map of melange configs we loaded at the start
	pc, ok := o.PackageConfigs[packageName]
	if !ok {
		return "", fmt.Errorf("no melange config found for package %s", packageName)
	}

	// if manual update create an issue rather than a pull request
	if pc.Config.Update.Manual {
		return o.createNewVersionIssue(ctx, repo, packageName, newVersion)
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("failed to get git worktree: %w", err)
	}

	root := worktree.Filesystem.Root()
	log.Printf("working directory: %s", root)

	configFile := filepath.Join(root, pc.Filename)
	if configFile == "" {
		return "", fmt.Errorf("no config filename found for package %s", packageName)
	}

	log.Printf("updating %s to version %s commit %s", packageName, newVersion.Version, newVersion.Commit)

	// if new versions are available lets bump the packages in the target melange git repo
	err = melange.Bump(ctx, configFile, newVersion.Version, newVersion.Commit)
	if err != nil {
		// add this to the list of messages to print at the end of the update
		return fmt.Sprintf("failed to bump package %s to version %s: %s", packageName, newVersion.Version, err.Error()), nil
	}

	// if the new version has a bump epoch flag set, increment the epoch
	// this can happen if we have a new expected commit sha but the version hasn't changed
	if newVersion.BumpEpoch {
		pc.Config.Package.Epoch++
	}

	rs, err := debug(worktree)
	if err != nil {
		return "", err
	}
	o.Logger.Printf("after bump: %s git status: %s", packageName, string(rs))

	// for now wolfi is using a Makefile, if it exists check if the package is listed and update the version + epoch if it is
	err = o.updateMakefile(root, packageName, newVersion.Version, worktree)
	if err != nil {
		return fmt.Sprintf("failed to update Makefile: %s", err.Error()), nil
	}

	// now make sure update config is configured
	updated, err := config.ParseConfiguration(ctx, filepath.Join(root, pc.Filename))
	if err != nil {
		return "", fmt.Errorf("failed to parse %v", err)
	}
	pctx := &melangebuild.PipelineBuild{
		Build: &melangebuild.Build{
			Configuration: *updated,
		},
		Package: &updated.Package,
	}

	// get a map of variable mutations we can substitute vars in URLs
	mutations, err := melangebuild.MutateWith(pctx, map[string]string{})
	if err != nil {
		return "", err
	}

	// Skip any processing for definitions with a single pipeline
	if len(updated.Pipeline) > 1 && deps.ContainsGoBumpPipeline(updated) {
		if err := o.updateGoBumpDeps(updated, root, pc.Filename, mutations); err != nil {
			return fmt.Sprintf("error cleaning up go/bump deps: %v", err), nil
		}
	}

	rs, err = debug(worktree)
	if err != nil {
		return "", err
	}
	o.Logger.Printf("after clean go bumps: %s git status: %s", packageName, string(rs))

	// Run yam formatter
	err = yam.FormatConfigurationFile(root, pc.Filename)
	if err != nil {
		return fmt.Sprintf("failed to format configuration file: %v", err), nil
	}

	_, err = worktree.Add(pc.Filename)
	if err != nil {
		return "", fmt.Errorf("failed to git add %s: %w", configFile, err)
	}

	// if we're not running in batch mode, lets commit and PR each change
	if !o.DryRun {
		pr, err := o.proposeChanges(ctx, repo, ref, packageName, newVersion)
		if err != nil {
			return fmt.Sprintf("failed to propose changes: %s", err.Error()), nil
		}
		if pr != "" {
			o.Logger.Println(color.GreenString(pr))
		}
	}
	return "", nil
}

func (o *Options) updateGoBumpDeps(updated *config.Configuration, dir, filename string, mutations map[string]string) error {
	yamlContent, err := os.ReadFile(filepath.Join(dir, filename))
	if err != nil {
		return err
	}
	var doc yaml.Node
	err = yaml.Unmarshal(yamlContent, &doc)
	if err != nil {
		return fmt.Errorf("error unmarshalling YAML: %v", err)
	}
	// NOTE: By default, we set tidy to false because we don´t want to compile the go project during updates.
	tidy := false
	if err := deps.CleanupGoBumpDeps(&doc, updated, tidy, mutations); err != nil {
		return err
	}

	modifiedYAML, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("error marshaling YAML: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, filename), modifiedYAML, 0o600); err != nil {
		return fmt.Errorf("failed to write configuration file: %v", err)
	}

	return nil
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

// create a unique branch
func (o *Options) createBranch(repo *git.Repository) (plumbing.ReferenceName, error) {
	name := uuid.New().String()

	headRef, err := repo.Head()
	if err != nil {
		return "", fmt.Errorf("failed to get repository HEAD: %w", err)
	}

	// Create a unique branch to work from
	branchName := plumbing.NewBranchReferenceName(fmt.Sprintf("wolfictl-%s", name))

	// Create the branch reference pointing to the HEAD commit
	newBranchRef := plumbing.NewHashReference(branchName, headRef.Hash())

	// Set the new branch reference in the repository
	err = repo.Storer.SetReference(newBranchRef)
	if err != nil {
		return "", fmt.Errorf("failed to create temporary branch %s: %w", branchName, err)
	}

	wt, err := repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("failed to get the worktree: %w", err)
	}
	// check out the new branch
	err = wt.Checkout(&git.CheckoutOptions{
		Branch: newBranchRef.Name(),
	})
	if err != nil {
		return "", fmt.Errorf("failed to check out the new branch: %w", err)
	}

	return newBranchRef.Name(), nil
}

// commits package update changes and creates a pull request
func (o *Options) proposeChanges(ctx context.Context, repo *git.Repository, ref plumbing.ReferenceName, packageName string, newVersion NewVersionResults) (string, error) {
	gitURL, err := wgit.GetRemoteURL(repo)
	if err != nil {
		return "", fmt.Errorf("failed to find git origin URL: %w", err)
	}

	basePullRequest := gh.BasePullRequest{
		RepoName:              gitURL.Name,
		Owner:                 gitURL.Organisation,
		Branch:                ref.String(),
		PullRequestBaseBranch: o.PullRequestBaseBranch,
	}

	client := github.NewClient(o.GitHubHTTPClient.Client)

	gitOpts := gh.GitOptions{
		GithubClient: client,
		MaxRetries:   maxPullRequestRetries,
		Logger:       o.Logger,
	}

	// commit the changes
	if err = o.commitChanges(repo, packageName, newVersion.Version); err != nil {
		return "", fmt.Errorf("failed to commit changes: %w", err)
	}

	// todo jr remove if this doesn't help
	wt, err := repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("failed to get the worktree: %w", err)
	}
	rs, err := debug(wt)
	if err != nil {
		return "", err
	}
	o.Logger.Printf("proposeChanges: %s git status: %s", packageName, string(rs))

	gitAuth, err := wgit.GetGitAuth(o.RepoURI)
	if err != nil {
		return "", fmt.Errorf("failed to get git auth: %w", err)
	}

	// setup githubReleases auth using standard environment variables
	pushOpts := &git.PushOptions{
		RemoteName: "origin",
		Auth:       gitAuth,
	}

	// push the version update changes to our working branch
	if err := repo.Push(pushOpts); err != nil {
		if err.Error() == "authorization failed" {
			return "", fmt.Errorf("failed to auth with git provider, does your personal access token have the repo scope? https://github.com/settings/tokens/new?scopes=repo: %w", err)
		}
		return "", fmt.Errorf("failed to git push: %w", err)
	}

	// now let's create a pull request

	// if we have a single version use it in the PR title, this might be a batch with multiple versions so default to a simple title
	var title string
	if newVersion.Version != "" {
		title = fmt.Sprintf(o.PullRequestTitle, packageName, newVersion.Version)
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
	pr, err := gitOpts.OpenPullRequest(ctx, newPR)
	prLink := pr.GetHTMLURL()
	if err != nil {
		return "", fmt.Errorf("failed to create pull request: %w", err)
	}
	err = gitOpts.LabelIssue(ctx, newPR.Owner, newPR.RepoName, *pr.Number, &o.IssueLabels)
	if err != nil {
		log.Printf("Failed to apply labels [%s] to PR #%d", strings.Join(o.IssueLabels, ","), pr.Number)
	}
	if newVersion.ReplaceExistingPRNumber != 0 {
		err = gitOpts.ClosePullRequest(ctx, gitURL.Organisation, gitURL.Name, newVersion.ReplaceExistingPRNumber)
		if err != nil {
			return "", fmt.Errorf("failed to close pull request: %d: %w", newVersion.ReplaceExistingPRNumber, err)
		}

		// comment on the closed PR the new pull request link which supersedes it
		comment := fmt.Sprintf("superseded by %s", prLink)
		_, err = gitOpts.CommentIssue(ctx, gitURL.Organisation, gitURL.Name, comment, newVersion.ReplaceExistingPRNumber)
		if err != nil {
			return "", fmt.Errorf("failed to comment pull request: %d: %w", newVersion.ReplaceExistingPRNumber, err)
		}
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
			return fmt.Errorf("failed to git sign commit %s: %w", rs, err)
		}
	} else {
		if _, err = worktree.Commit(commitMessage, commitOpts); err != nil {
			return fmt.Errorf("failed to git commit: %w", err)
		}
	}
	return nil
}

func (o *Options) createErrorMessageIssue(ctx context.Context, repo *git.Repository, packageName, message string) (string, error) {
	gitURL, err := wgit.GetRemoteURL(repo)
	if err != nil {
		return "", fmt.Errorf("failed to find git origin URL: %w", err)
	}

	client := github.NewClient(o.GitHubHTTPClient.Client)
	gitOpts := gh.GitOptions{
		GithubClient: client,
		MaxRetries:   maxPullRequestRetries,
		Logger:       o.Logger,
	}

	i := &gh.Issues{
		Owner:       gitURL.Organisation,
		RepoName:    gitURL.Name,
		PackageName: packageName,
		Comment:     message,
		Title:       gh.GetErrorIssueTitle(bot, packageName),
		Labels:      o.IssueLabels,
	}
	existingIssue, err := gitOpts.CheckExistingIssue(ctx, i)
	if err != nil {
		return "", err
	}

	if existingIssue > 0 {
		exists, err := gitOpts.HasExistingComment(ctx, i, existingIssue, message)
		if exists {
			return fmt.Sprintf("existing issue %d already exists for error message: %s", existingIssue, message), err
		}
		// if this is a new error add a new comment
		return gitOpts.CommentIssue(ctx, gitURL.Organisation, gitURL.Name, message, existingIssue)
	}

	return gitOpts.OpenIssue(ctx, i)
}

func (o *Options) createNewVersionIssue(ctx context.Context, repo *git.Repository, packageName string, version NewVersionResults) (string, error) {
	gitURL, err := wgit.GetRemoteURL(repo)
	if err != nil {
		return "", fmt.Errorf("failed to find git origin URL: %w", err)
	}

	client := github.NewClient(o.GitHubHTTPClient.Client)
	gitOpts := gh.GitOptions{
		GithubClient: client,
		MaxRetries:   maxPullRequestRetries,
		Logger:       o.Logger,
	}

	i := &gh.Issues{
		Owner:       gitURL.Organisation,
		RepoName:    gitURL.Name,
		PackageName: packageName,
		Title:       gh.GetUpdateIssueTitle(packageName, version.Version),
		Labels:      o.IssueLabels,
	}

	existingIssues, err := gitOpts.ListIssues(ctx, gitURL.Organisation, gitURL.Name, "open")
	if err != nil {
		return "", err
	}

	// if the issue already exists then don't create a new one
	for _, issue := range existingIssues {
		if *issue.Title == i.Title {
			return "", nil
		}
	}

	// create a new issue
	issueLink, err := gitOpts.OpenIssue(ctx, i)
	if err != nil {
		return "", err
	}
	o.Logger.Println(color.GreenString(fmt.Sprintf("%s opened issue %s", packageName, issueLink)))

	// if there's an existing issue with the same package but older version then close it
	for _, issue := range existingIssues {
		if strings.HasPrefix(*issue.Title, packageName+"/") {
			err = gitOpts.CloseIssue(ctx, gitURL.Organisation, gitURL.Name, fmt.Sprintf("superseded by %s", issueLink), *issue.Number)
			if err != nil {
				return "", err
			}
		}
	}

	return "", nil
}

func (o *Options) getPackagesToUpdate(latestVersions map[string]NewVersionResults) (map[string]NewVersionResults, error) {
	results := make(map[string]NewVersionResults)

	for packageName, v := range latestVersions {
		pc, ok := o.PackageConfigs[packageName]
		if !ok {
			return nil, fmt.Errorf("failed to match latest version package name %s with local melange packages", packageName)
		}
		c := pc.Config
		currentVersionSemver, err := wolfiversions.NewVersion(c.Package.Version)
		if err != nil {
			return nil, fmt.Errorf("failed to create a version from package %s: %s: %w", c.Package.Name, c.Package.Version, err)
		}

		latestVersionSemver, err := wolfiversions.NewVersion(v.Version)
		if err != nil {
			return nil, fmt.Errorf("failed to create a latest version from package %s: %s: %w", c.Package.Name, c.Package.Version, err)
		}

		if currentVersionSemver.Equal(latestVersionSemver) {
			o.Logger.Printf(
				"%s is on the latest version %s",
				c.Package.Name, latestVersionSemver.Original(),
			)
		}
		if currentVersionSemver.LessThan(latestVersionSemver) {
			o.Logger.Println(
				color.GreenString(
					fmt.Sprintf("there is a new stable version available %s, current wolfi version %s, new %s",
						c.Package.Name, c.Package.Version, latestVersionSemver.Original())))

			results[c.Package.Name] = NewVersionResults{Version: latestVersionSemver.Original(), Commit: v.Commit}
		}

		// if versions match but the commit doesn't then we need to update the commit
		// this can occur when an upstream project recreated a tag with a new commit
		// if release monitor was used we won't have a commit sha
		if v.Commit == "" {
			continue
		}
		if currentVersionSemver.Equal(latestVersionSemver) {
			for i := range pc.Config.Pipeline {
				pipeline := &pc.Config.Pipeline[i]
				if pipeline.Uses == "git-checkout" {
					expectedCommit := pipeline.With["expected-commit"]

					if expectedCommit != "" && expectedCommit != v.Commit {
						o.Logger.Printf(
							color.YellowString("expected commit %s does not match latest commit %s for package %s", pipeline.With["expected-commit"], v.Commit, c.Package.Name))

						results[c.Package.Name] = NewVersionResults{Version: latestVersionSemver.Original(), Commit: v.Commit, BumpEpoch: true}
						break
					}
				}
			}
		}
	}
	return results, nil
}

// return updated map if an existing issue or pr for an older version should be closed
// will also remove an update if we already have an open matching pull request or issue
func (o *Options) removeExistingUpdates(ctx context.Context, repo *git.Repository) error {
	gitURL, err := wgit.GetRemoteURL(repo)
	if err != nil {
		return fmt.Errorf("failed to find git origin URL: %w", err)
	}

	client := github.NewClient(o.GitHubHTTPClient.Client)
	gitOpts := gh.GitOptions{
		GithubClient: client,
		MaxRetries:   maxPullRequestRetries,
		Logger:       o.Logger,
	}

	openPRs, err := gitOpts.ListPullRequests(ctx, gitURL.Organisation, gitURL.Name, "open")
	if err != nil {
		return fmt.Errorf("failed to list open pull requests for %s/%s: %w", gitURL.Organisation, gitURL.Name, err)
	}

	o.removeExistingPullRequests(openPRs)

	openIssues, err := gitOpts.ListIssues(ctx, gitURL.Organisation, gitURL.Name, "open")
	if err != nil {
		return fmt.Errorf("failed to list open issues for %s/%s: %w", gitURL.Organisation, gitURL.Name, err)
	}

	o.removeExistingIssues(openIssues)

	return nil
}

func (o *Options) removeExistingPullRequests(prs []*github.PullRequest) {
	for _, pr := range prs {
		prTitle := *pr.Title

		packageName, titleVersion, err := extractPackageVersionFromTitle(prTitle)
		if err != nil {
			// ignore if we can't extract a package name and version string
			continue
		}

		v, ok := o.PackagesToUpdate[packageName]
		if !ok {
			continue
		}

		if o.isSameVersion(packageName, v.Version, prTitle) {
			o.Logger.Printf("pull request %s already exists for %s\n", *pr.HTMLURL, prTitle)
			delete(o.PackagesToUpdate, packageName)
			continue
		}

		if o.containsOldVersion(packageName, v.Version, titleVersion, prTitle) {
			v.ReplaceExistingPRNumber = *pr.Number
			o.PackagesToUpdate[packageName] = v
		}
	}
}

func (o *Options) removeExistingIssues(issues []*github.Issue) {
	for _, issue := range issues {
		issueTitle := *issue.Title

		packageName, titleVersion, err := extractPackageVersionFromTitle(issueTitle)
		if err != nil {
			// ignore if we can't extract a package name and version string
			continue
		}

		v, ok := o.PackagesToUpdate[packageName]
		if !ok {
			continue
		}

		if o.isSameVersion(packageName, v.Version, issueTitle) {
			delete(o.PackagesToUpdate, packageName)
			continue
		}

		if o.containsOldVersion(packageName, v.Version, titleVersion, issueTitle) {
			v.ReplaceExistingPRNumber = *issue.Number
			o.PackagesToUpdate[packageName] = v
		}
	}
}

func (o *Options) isSameVersion(packageName, version, title string) bool {
	return strings.HasPrefix(title, fmt.Sprintf("%s/%s", packageName, version))
}

// checks if a version in a pull request or issue title is older that the latest available version
func (o *Options) containsOldVersion(packageName, latestVersionStr, titleVersionStr, title string) bool {
	prefix := fmt.Sprintf("%s/", packageName)

	if !strings.HasPrefix(title, prefix) {
		return false
	}

	currentVersion, err := wolfiversions.NewVersion(titleVersionStr)
	if err != nil {
		// ignore if we can't create a real version
		return false
	}

	latestVersion, err := wolfiversions.NewVersion(latestVersionStr)
	if err != nil {
		o.Logger.Printf("cannot get new version from version %s. Error %s", latestVersionStr, err.Error())
		return false
	}

	return currentVersion.LessThan(latestVersion)
}

// grab the package name and version from a title similar to "package_name/1.2.3 package update"
func extractPackageVersionFromTitle(title string) (packageName, version string, err error) {
	parts := strings.SplitAfter(title, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("cannot split title %s", title)
	}

	versionParts := strings.SplitAfter(parts[1], " ")
	if len(versionParts) == 0 {
		return "", "", fmt.Errorf("cannot split version %s", parts[1])
	}

	version = strings.TrimSpace(versionParts[0])
	packageName = strings.TrimSuffix(parts[0], "/")
	return
}
