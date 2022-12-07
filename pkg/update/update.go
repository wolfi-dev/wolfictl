package update

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	gitHttp "github.com/go-git/go-git/v5/plumbing/transport/http"

	"github.com/google/uuid"
	"github.com/wolfi-dev/wolfictl/pkg/gh"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/go-github/v48/github"
	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
)

type Options struct {
	PackageNames          []string
	PullRequestBaseBranch string
	PullRequestTitle      string
	RepoURI               string
	DataMapperURL         string
	DefaultBranch         string
	Batch                 bool
	DryRun                bool
	Packages              map[string]MelageConfig
	Client                *RLHTTPClient
	Logger                *log.Logger
	GitHubHTTPClient      *RLHTTPClient
}

const (
	secondsToSleepWhenRateLimited = 30
	maxPullRequestRetries         = 10
	wolfiImage                    = `
<p align="center">
  <img src="https://raw.githubusercontent.com/wolfi-dev/.github/main/profile/wolfi-logo-light-mode.svg" />
</p>
`
)

// New initialise including a map of existing wolfios packages
func New() (Options, error) {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)

	options := Options{

		Client: &RLHTTPClient{
			client: http.DefaultClient,

			// 1 request every (n) second(s) to avoid DOS'ing server
			Ratelimiter: rate.NewLimiter(rate.Every(2*time.Second), 1),
		},
		GitHubHTTPClient: &RLHTTPClient{
			client: oauth2.NewClient(context.Background(), ts),

			// 1 request every (n) second(s) to avoid DOS'ing server. https://docs.github.com/en/rest/guides/best-practices-for-integrators?apiVersion=2022-11-28#dealing-with-secondary-rate-limits
			Ratelimiter: rate.NewLimiter(rate.Every(3*time.Second), 1),
		},
		Logger: log.New(log.Writer(), "wolfictl: ", log.LstdFlags|log.Lmsgprefix),
	}

	options.Packages = make(map[string]MelageConfig)
	options.DefaultBranch = "main"
	return options, nil
}

func (o Options) Update() error {

	// clone the melange config git repo into a temp folder so we can work with it
	tempDir, err := os.MkdirTemp("", "wolfictl")
	if err != nil {
		return errors.Wrapf(err, "failed to create temporary folder to clone package configs into")
	}
	if o.DryRun {
		o.Logger.Printf("using working directory %s", tempDir)
	} else {
		defer os.Remove(tempDir)
	}

	repo, err := git.PlainClone(tempDir, false, &git.CloneOptions{
		URL:      o.RepoURI,
		Progress: os.Stdout,
	})
	if err != nil {
		return errors.Wrapf(err, "failed to clone repository %s into %s", o.RepoURI, tempDir)
	}

	// first, let's get the package(s) we want to check for updates
	err = o.readPackageConfigs(tempDir)
	if err != nil {
		return errors.Wrapf(err, "failed to get package configs")
	}

	// second, check service for new package versions
	m := MonitorService{Client: o.Client, Logger: o.Logger, DataMapperURL: o.DataMapperURL}
	mapperData, err := m.getMonitorServiceData()
	if err != nil {
		return errors.Wrapf(err, "failed getting release monitor service mapping data")
	}

	packagesToUpdate := make(map[string]string)

	// iterate packages in the target git repo and check if a new version is available
	for _, config := range o.Packages {
		item := mapperData[config.Package.Name]
		if item.Identifier == "" {
			continue
		}

		latestVersion, err := m.getLatestReleaseVersion(item.Identifier)
		if err != nil {
			return errors.Wrapf(err, "failed getting latest release version for package %s, identifier %s", config.Package.Name, item.Identifier)
		}

		currentVersionSemver, err := version.NewVersion(config.Package.Version)
		if err != nil {
			o.Logger.Printf("failed to create a version from package %s: %s.  Error: %s", config.Package.Name, config.Package.Version, err)
			continue
		}

		latestVersionSemver, err := version.NewVersion(latestVersion)
		if err != nil {
			o.Logger.Printf("failed to create a version from package %s: %s.  Error: %s", config.Package.Name, latestVersion, err)
			continue
		}

		if currentVersionSemver.LessThan(latestVersionSemver) {
			o.Logger.Printf("there is a new stable version available %s %s, current wolfi version %s", config.Package.Name, latestVersion, config.Package.Version)
			packagesToUpdate[config.Package.Name] = latestVersion
		}
	}

	return o.updatePackagesGitRepository(repo, packagesToUpdate, tempDir)

}

// function will iterate over all packages that need to be updated and create a pull request for each change by default unless batch mode which creates a single pull request
func (o Options) updatePackagesGitRepository(repo *git.Repository, packagesToUpdate map[string]string, tempDir string) error {
	var ref plumbing.ReferenceName
	var err error
	var pullRequests []string

	if o.Batch {
		// let's work on a branch when updating package versions, so we can create a PR from that branch later
		ref, err = o.switchBranch(repo)
		if err != nil {
			return errors.Wrapf(err, "failed to switch to working git branch")
		}
	}

	// bump packages that need updating
	for packageName, latestVersion := range packagesToUpdate {

		// if not batch mode create a branch for each package change
		if !o.Batch {
			// let's work on a branch when updating package versions, so we can create a PR from that branch later
			ref, err = o.switchBranch(repo)
			if err != nil {
				return errors.Wrapf(err, "failed to switch to working git branch")
			}
		}

		configFile := filepath.Join(tempDir, packageName+".yaml")

		// if new versions are available lets bump the packages in the target melange git repo
		err := o.bump(configFile, latestVersion)
		if err != nil {
			o.Logger.Printf("failed to bump config file %s to version %s: %s", configFile, latestVersion, err.Error())
			continue
		}
		worktree, err := repo.Worktree()
		if err != nil {
			return errors.Wrapf(err, "failed to get git worktree")
		}
		_, err = worktree.Add(packageName + ".yaml")
		if err != nil {
			return errors.Wrapf(err, "failed to git add %s", configFile)
		}

		// for now wolfi is using a Makefile, if it exists check if the package is listed and update the version + epoch if it is
		err = o.updateMakefile(tempDir, packageName, latestVersion, worktree)
		if err != nil {
			return errors.Wrap(err, "failed to update Makefile")
		}

		// if we're not running in batch mode, lets commit and PR each change
		if !o.Batch && !o.DryRun {
			pr, err := o.proposeChanges(repo, ref, packageName, latestVersion)
			if err != nil {
				return errors.Wrap(err, "failed to commit changes")
			}
			if pr != "" {
				pullRequests = append(pullRequests, pr)
			}
		}
	}

	// create the single pull request at the end if running in batch mode
	if o.Batch && !o.DryRun {
		pr, err := o.proposeChanges(repo, ref, "Batch", "")
		if err != nil {
			return errors.Wrap(err, "failed to commit changes")
		}
		pullRequests = append(pullRequests, pr)
	}

	// print out pull request links
	for _, pr := range pullRequests {
		o.Logger.Printf(pr)
	}
	return nil
}

// this feels very hacky but the Makefile is going away with help from Dag so plan to delete this func soon
// for now wolfi is using a Makefile, if it exists check if the package is listed and update the version + epoch if it is
func (o Options) updateMakefile(tempDir string, packageName string, latestVersion string, worktree *git.Worktree) error {
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
		return errors.Wrap(err, "failed to check file permissions of the Makefile")
	}

	err = os.WriteFile(filepath.Join(tempDir, "Makefile"), newFile, info.Mode())
	if err != nil {
		return errors.Wrap(err, "failed to write Makefile")
	}
	_, err = worktree.Add("Makefile")
	if err != nil {
		return errors.Wrap(err, "failed to git add Makefile")
	}
	return nil
}

// create a unique branch
func (o Options) switchBranch(repo *git.Repository) (plumbing.ReferenceName, error) {
	name := uuid.New().String()

	worktree, err := repo.Worktree()
	if err != nil {
		return "", errors.Wrapf(err, "failed to get git worktree")
	}

	// make sure we are on the main branch to start with
	ref := plumbing.ReferenceName(fmt.Sprintf("refs/heads/" + o.DefaultBranch))

	err = worktree.Checkout(&git.CheckoutOptions{
		Create: false,
		Branch: ref,
	})
	if err != nil {
		return "", errors.Wrap(err, "failed to checkout main")
	}

	// create a unique branch to work from
	ref = plumbing.ReferenceName(fmt.Sprintf("refs/heads/wolfictl-%v", name))
	err = worktree.Checkout(&git.CheckoutOptions{
		Create: true,
		Branch: ref,
	})

	if err != nil {
		return "", errors.Wrap(err, "failed to checkout to temporary branch")
	}

	return ref, err
}

// read the melange package config(s) from the target git repository so we can check if new versions exist
func (o Options) readPackageConfigs(tempDir string) error {
	var err error

	if len(o.PackageNames) > 0 {
		// get package by name
		for _, packageName := range o.PackageNames {
			filename := filepath.Join(tempDir, packageName+".yaml")
			err = o.readPackageConfig(filename)
			if err != nil {
				return errors.Wrapf(err, "failed to read package config %s", filename)
			}
		}

	} else {
		// get all packages in the provided git repo
		err = o.readAllPackagesFromRepo(tempDir)
		if err != nil {
			return errors.Wrapf(err, "failed to read package configs from repo %s", o.RepoURI)
		}
	}
	return nil
}

// commits package update changes and creates a pull request
func (o Options) proposeChanges(repo *git.Repository, ref plumbing.ReferenceName, packageName, newVersion string) (string, error) {

	remote, err := repo.Remote("origin")
	if err != nil {
		return "", errors.Wrapf(err, "failed to find git origin URL")
	}

	if len(remote.Config().URLs) == 0 {
		return "", fmt.Errorf("no remote config URLs found for remote origin")
	}

	owner, repoName, err := parseGitURL(remote.Config().URLs[0])
	if err != nil {
		return "", errors.Wrapf(err, "failed to find git origin URL")
	}

	basePullRequest := gh.BasePullRequest{
		RepoName:              repoName,
		Owner:                 owner,
		Branch:                ref.String(),
		PullRequestBaseBranch: o.PullRequestBaseBranch,
		Retries:               0,
	}

	client := github.NewClient(o.GitHubHTTPClient.client)
	gitOpts := gh.GitOptions{
		GithubClient:                  client,
		MaxPullRequestRetries:         maxPullRequestRetries,
		SecondsToSleepWhenRateLimited: secondsToSleepWhenRateLimited,
		Logger:                        o.Logger,
	}

	getPr := gh.GetPullRequest{
		BasePullRequest: basePullRequest,
		PackageName:     packageName,
		Version:         newVersion,
	}

	// if an existing PR is open with the same version skip, if it's an older version close the PR and we'll create a new one
	exitingPR, err := gitOpts.CheckExistingPullRequests(getPr)
	if err != nil {
		return "", errors.Wrapf(err, "failed to check for existing pull requests")
	}

	if exitingPR != "" {
		o.Logger.Printf("found matching open pull request for %s/%s %s", packageName, newVersion, exitingPR)
		return "", nil
	}

	// commit the changes
	err = o.commitChanges(repo, packageName, newVersion)
	if err != nil {
		return "", errors.Wrap(err, "failed to commit changes")
	}

	// setup github auth using standard environment variables
	pushOpts := &git.PushOptions{RemoteName: "origin"}
	gitToken := os.Getenv("GITHUB_TOKEN")
	if gitToken != "" {
		pushOpts.Auth = &gitHttp.BasicAuth{
			Username: "abc123",
			Password: gitToken,
		}
	}

	// push the version update changes to our working branch
	err = repo.Push(pushOpts)
	if err != nil {
		return "", errors.Wrapf(err, "failed to git push")
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
	newPR := gh.NewPullRequest{
		BasePullRequest: basePullRequest,
		Title:           title,
		Body:            wolfiImage,
	}

	// create the pull request
	prLink, err := gitOpts.OpenPullRequest(newPR)
	if err != nil {
		return "", errors.Wrapf(err, "failed to create pull request")
	}

	return prLink, nil
}

// commit changes to git
func (o Options) commitChanges(repo *git.Repository, packageName, latestVersion string) error {
	worktree, err := repo.Worktree()
	if err != nil {
		return errors.Wrapf(err, "failed to get git worktree")
	}

	commitMessage := ""
	if latestVersion != "" {
		commitMessage = fmt.Sprintf("%s/%s package update", packageName, latestVersion)
	} else {
		commitMessage = "Updating wolfi packages"
	}
	_, err = worktree.Commit(commitMessage, &git.CommitOptions{})
	if err != nil {
		return errors.Wrapf(err, "failed to git commit")
	}
	return nil
}

func parseGitURL(rawURL string) (string, string, error) {
	rawURL = strings.TrimSuffix(rawURL, ".git")

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", "", errors.Wrapf(err, "failed to parse git url %s", rawURL)
	}

	parts := strings.Split(parsedURL.Path, "/")
	return parts[1], parts[2], nil
}
