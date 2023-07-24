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

	wolfiversions "github.com/wolfi-dev/wolfictl/pkg/versions"

	"github.com/fatih/color"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/go-github/v50/github"
	"github.com/google/uuid"
	"github.com/pkg/errors"
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
	Client                 *http2.RLHTTPClient
	Logger                 *log.Logger
	GitHubHTTPClient       *http2.RLHTTPClient
	ErrorMessages          map[string]string
	IssueLabels            []string
	MaxRetries             int
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
func New() Options {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)
	options := Options{
		Client: &http2.RLHTTPClient{
			Client: http.DefaultClient,

			// 1 request every (n) second(s) to avoid DOS'ing server
			Ratelimiter: rate.NewLimiter(rate.Every(5*time.Second), 1),
		},
		GitHubHTTPClient: &http2.RLHTTPClient{
			Client: oauth2.NewClient(context.Background(), ts),

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
	var packagesToUpdate map[string]NewVersionResults

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

		cloneOpts := &git.CloneOptions{
			URL:               o.RepoURI,
			Progress:          os.Stdout,
			RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
			Auth:              wgit.GetGitAuth(),
			Depth:             1,
		}

		repo, err = git.PlainClone(tempDir, false, cloneOpts)
		if err != nil {
			return fmt.Errorf("failed to clone repository %s into %s: %w", o.RepoURI, tempDir, err)
		}

		// get the latest upstream versions available
		if latestVersions == nil {
			latestVersions, err = o.GetLatestVersions(tempDir, o.PackageNames)
			if err != nil {
				return errors.Wrapf(err, "failed to get package updates")
			}
		}

		// compare latest upstream versions with melange package versions and return a map of packages to update
		if packagesToUpdate == nil {
			packagesToUpdate, err = o.getPackagesToUpdate(latestVersions)
			if err != nil {
				return errors.Wrapf(err, "failed to get package updates")
			}
		}

		// skip packages for which we already have an open issue or pull request
		packagesToUpdate, err = o.removeExistingUpdates(repo, packagesToUpdate)
		if err != nil {
			return errors.Wrapf(err, "failed to get package updates")
		}

		// update melange configs in our cloned git repository with any new package versions
		err = o.updatePackagesGitRepository(ctx, repo, packagesToUpdate)
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
		if o.CreateIssues {
			issueURL, err := o.createErrorMessageIssue(repo, k, message)
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

func (o *Options) GetLatestVersions(dir string, packageNames []string) (map[string]NewVersionResults, error) {
	var err error
	latestVersions := make(map[string]NewVersionResults)

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
			Client: o.Client,
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

// function will iterate over all packages that need to be updated and create a pull request for each change by default unless batch mode which creates a single pull request
func (o *Options) updatePackagesGitRepository(ctx context.Context, repo *git.Repository, packagesToUpdate map[string]NewVersionResults) error {
	// store the HEAD ref to switch back later
	headRef, err := repo.Head()
	if err != nil {
		return errors.Wrap(err, "failed to get the HEAD ref")
	}

	// Bump packages that need updating
	for packageName, newVersion := range packagesToUpdate {
		// todo jr remove if this doesn't help
		// add sleep to see if it helps intermittent "object not found" when pushing
		time.Sleep(1 * time.Second)

		wt, err := repo.Worktree()
		if err != nil {
			return errors.Wrap(err, "failed to get the worktree")
		}
		// make sure we are on HEAD
		err = wt.Checkout(&git.CheckoutOptions{
			Branch: headRef.Name(),
		})
		if err != nil {
			return errors.Wrap(err, "failed to check out HEAD")
		}

		// todo jr remove if this doesn't help
		rs, err := debug(wt)
		if err != nil {
			return err
		}
		o.Logger.Printf("updatePackagesGitRepository: %s git status: %s", packageName, string(rs))

		// let's work on a branch when updating package versions, so we can create a PR from that branch later
		ref, err := o.createBranch(repo)
		if err != nil {
			return errors.Wrap(err, "failed to create git branch")
		}

		errorMessage, err := o.updateGitPackage(ctx, repo, packageName, newVersion, ref)
		if err != nil {
			return err
		}
		if errorMessage != "" {
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
		return nil, errors.Wrapf(err, "failed run git status %s", rs)
	}
	return rs, nil
}

func (o *Options) updateGitPackage(ctx context.Context, repo *git.Repository, packageName string, newVersion NewVersionResults, ref plumbing.ReferenceName) (string, error) {
	// get the filename from the map of melange configs we loaded at the start
	config, ok := o.PackageConfigs[packageName]
	if !ok {
		return "", fmt.Errorf("no melange config found for package %s", packageName)
	}

	// if manual update create an issue rather than a pull request
	if config.Config.Update.Manual {
		return o.createNewVersionIssue(repo, packageName, newVersion)
	}

	configFile := filepath.Join(config.Dir, config.Filename)
	if configFile == "" {
		return "", fmt.Errorf("no config filename found for package %s", packageName)
	}

	// if new versions are available lets bump the packages in the target melange git repo
	err := melange.Bump(ctx, configFile, newVersion.Version, newVersion.Commit)
	if err != nil {
		// add this to the list of messages to print at the end of the update
		return fmt.Sprintf("failed to bump package %s to version %s: %s", packageName, newVersion.Version, err.Error()), nil
	}

	// if the new version has a bump epoch flag set, increment the epoch
	// this can happen if we have a new expected commit sha but the version hasn't changed
	if newVersion.BumpEpoch {
		config.Config.Package.Epoch++
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
	err = o.updateMakefile(config.Dir, packageName, newVersion.Version, worktree)
	if err != nil {
		return fmt.Sprintf("failed to update Makefile: %s", err.Error()), nil
	}

	// if mapping data has a strip prefix, add it back in to the version for when updating git modules
	latestVersionWithPrefix := newVersion.Version
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
		pr, err := o.proposeChanges(repo, ref, packageName, newVersion)
		if err != nil {
			return fmt.Sprintf("failed to propose changes: %s", err.Error()), nil
		}
		if pr != "" {
			o.Logger.Println(color.GreenString(pr))
		}
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
func (o *Options) createBranch(repo *git.Repository) (plumbing.ReferenceName, error) {
	name := uuid.New().String()

	headRef, err := repo.Head()
	if err != nil {
		return "", errors.Wrap(err, "failed to get repository HEAD")
	}

	// Create a unique branch to work from
	branchName := plumbing.NewBranchReferenceName(fmt.Sprintf("wolfictl-%s", name))

	// Create the branch reference pointing to the HEAD commit
	newBranchRef := plumbing.NewHashReference(branchName, headRef.Hash())

	// Set the new branch reference in the repository
	err = repo.Storer.SetReference(newBranchRef)
	if err != nil {
		return "", errors.Wrapf(err, "failed to create temporary branch %s", branchName)
	}

	wt, err := repo.Worktree()
	if err != nil {
		return "", errors.Wrap(err, "failed to get the worktree")
	}
	// check out the new branch
	err = wt.Checkout(&git.CheckoutOptions{
		Branch: newBranchRef.Name(),
	})
	if err != nil {
		return "", errors.Wrap(err, "failed to check out the new branch")
	}

	return newBranchRef.Name(), nil
}

// commits package update changes and creates a pull request
func (o *Options) proposeChanges(repo *git.Repository, ref plumbing.ReferenceName, packageName string, newVersion NewVersionResults) (string, error) {
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
		return "", errors.Wrap(err, "failed to get the worktree")
	}
	rs, err := debug(wt)
	if err != nil {
		return "", err
	}
	o.Logger.Printf("proposeChanges: %s git status: %s", packageName, string(rs))

	// setup githubReleases auth using standard environment variables
	pushOpts := &git.PushOptions{
		RemoteName: "origin",
		Auth:       wgit.GetGitAuth(),
		Progress:   os.Stdout, // todo remove if this doesn't help: extra logging to help debug intermittent "object not found" when pushing
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
	pr, err := gitOpts.OpenPullRequest(newPR)
	prLink := pr.GetHTMLURL()
	if err != nil {
		return "", fmt.Errorf("failed to create pull request: %w", err)
	}
	err = gitOpts.LabelIssue(context.Background(), newPR.Owner, newPR.RepoName, *pr.Number, &o.IssueLabels)
	if err != nil {
		log.Printf("Failed to apply labels [%s] to PR #%d", strings.Join(o.IssueLabels, ","), pr.Number)
	}
	if newVersion.ReplaceExistingPRNumber != 0 {
		err = gitOpts.ClosePullRequest(context.Background(), gitURL.Organisation, gitURL.Name, newVersion.ReplaceExistingPRNumber)
		if err != nil {
			return "", errors.Wrapf(err, "failed to close pull request: %d", newVersion.ReplaceExistingPRNumber)
		}

		// comment on the closed PR the new pull request link which supersedes it
		comment := fmt.Sprintf("superceded by %s", prLink)
		_, err = gitOpts.CommentIssue(context.Background(), gitURL.Organisation, gitURL.Name, comment, newVersion.ReplaceExistingPRNumber)
		if err != nil {
			return "", errors.Wrapf(err, "failed to comment pull request: %d", newVersion.ReplaceExistingPRNumber)
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
			return errors.Wrapf(err, "failed to git sign commit %s", rs)
		}
	} else {
		if _, err = worktree.Commit(commitMessage, commitOpts); err != nil {
			return fmt.Errorf("failed to git commit: %w", err)
		}
	}
	return nil
}

func (o *Options) createErrorMessageIssue(repo *git.Repository, packageName, message string) (string, error) {
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
	existingIssue, err := gitOpts.CheckExistingIssue(context.Background(), i)
	if err != nil {
		return "", err
	}

	if existingIssue > 0 {
		exists, err := gitOpts.HasExistingComment(context.Background(), i, existingIssue, message)
		if exists {
			return fmt.Sprintf("existing issue %d already exists for error message: %s", existingIssue, message), err
		}
		// if this is a new error add a new comment
		return gitOpts.CommentIssue(context.Background(), gitURL.Organisation, gitURL.Name, message, existingIssue)
	}

	return gitOpts.OpenIssue(context.Background(), i)
}

func (o *Options) createNewVersionIssue(repo *git.Repository, packageName string, version NewVersionResults) (string, error) {
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

	existingIssues, err := gitOpts.ListIssues(context.Background(), gitURL.Organisation, gitURL.Name, "open")
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
	issueLink, err := gitOpts.OpenIssue(context.Background(), i)
	if err != nil {
		return "", err
	}
	o.Logger.Println(color.GreenString(fmt.Sprintf("%s opened issue %s", packageName, issueLink)))

	// if there's an existing issue with the same package but older version then close it
	for _, issue := range existingIssues {
		if strings.HasPrefix(*issue.Title, packageName+"/") {
			err = gitOpts.CloseIssue(context.Background(), gitURL.Organisation, gitURL.Name, fmt.Sprintf("superseded by %s", issueLink), *issue.Number)
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
			return nil, errors.Wrapf(err, "failed to create a version from package %s: %s", c.Package.Name, c.Package.Version)
		}

		latestVersionSemver, err := wolfiversions.NewVersion(v.Version)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create a latest version from package %s: %s", c.Package.Name, c.Package.Version)
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
		if currentVersionSemver.Equal(latestVersionSemver) {
			for i := range pc.Config.Pipeline {
				pipeline := &pc.Config.Pipeline[i]
				if pipeline.Uses == "git-checkout" {
					if pipeline.With["expected-commit"] != v.Commit {
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
func (o *Options) removeExistingUpdates(repo *git.Repository, updates map[string]NewVersionResults) (map[string]NewVersionResults, error) {
	gitURL, err := wgit.GetRemoteURL(repo)
	if err != nil {
		return updates, fmt.Errorf("failed to find git origin URL: %w", err)
	}

	client := github.NewClient(o.GitHubHTTPClient.Client)
	gitOpts := gh.GitOptions{
		GithubClient: client,
		MaxRetries:   maxPullRequestRetries,
		Logger:       o.Logger,
	}

	openPRs, err := gitOpts.ListPullRequests(context.Background(), gitURL.Organisation, gitURL.Name, "open")
	if err != nil {
		return updates, errors.Wrapf(err, "failed to list open pull requests for %s/%s", gitURL.Organisation, gitURL.Name)
	}

	o.processPullRequests(updates, openPRs)

	openIssues, err := gitOpts.ListIssues(context.Background(), gitURL.Organisation, gitURL.Name, "open")
	if err != nil {
		return updates, errors.Wrapf(err, "failed to list open issues for %s/%s", gitURL.Organisation, gitURL.Name)
	}

	o.processIssues(updates, openIssues)

	return updates, nil
}

func (o *Options) processPullRequests(updates map[string]NewVersionResults, prs []*github.PullRequest) {
	for _, pr := range prs {
		prTitle := *pr.Title

		packageName, titleVersion, err := extractPackageVersionFromTitle(prTitle)
		if err != nil {
			// ignore if we can't extract a package name and version string
			continue
		}

		v, ok := updates[packageName]
		if !ok {
			continue
		}

		if o.isSameVersion(packageName, v.Version, prTitle) {
			o.Logger.Printf("pull request %s already exists for %s\n", *pr.HTMLURL, prTitle)
			delete(updates, packageName)
			continue
		}

		if o.containsOldVersion(packageName, v.Version, titleVersion, prTitle) {
			v.ReplaceExistingPRNumber = *pr.Number
			updates[packageName] = v
		}
	}
}

func (o *Options) processIssues(updates map[string]NewVersionResults, issues []*github.Issue) {
	for _, issue := range issues {
		issueTitle := *issue.Title

		packageName, titleVersion, err := extractPackageVersionFromTitle(issueTitle)
		if err != nil {
			// ignore if we can't extract a package name and version string
			continue
		}

		v, ok := updates[packageName]
		if !ok {
			continue
		}

		if o.isSameVersion(packageName, v.Version, issueTitle) {
			delete(updates, packageName)
			continue
		}

		if o.containsOldVersion(packageName, v.Version, titleVersion, issueTitle) {
			v.ReplaceExistingPRNumber = *issue.Number
			updates[packageName] = v
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
