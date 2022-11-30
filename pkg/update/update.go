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

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	gitHttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-github/github"
	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
)

type Options struct {
	PackageName           string
	PullRequestBaseBranch string
	PullRequestTitle      string
	RepoURI               string
	Batch                 bool
	DryRun                bool
	Packages              map[string]MelageConfig
	Client                *RLHTTPClient
	Logger                *log.Logger
	GitHubHTTPClient      *http.Client
}

const wolfiImage = `
<p align="center">
  <img src="https://raw.githubusercontent.com/wolfi-dev/.github/main/profile/wolfi-logo-light-mode.svg" />
</p>
`

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
		GitHubHTTPClient: oauth2.NewClient(context.Background(), ts),
		Logger:           log.New(log.Writer(), "wolfictl: ", log.LstdFlags|log.Lmsgprefix),
	}

	options.Packages = make(map[string]MelageConfig)

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
	err = o.getPackageConfigs(tempDir)
	if err != nil {
		return errors.Wrapf(err, "failed to get package configs")
	}

	// second, check service for new package versions
	m := MonitorService{Client: o.Client, Logger: o.Logger}
	mapperData, err := m.getMonitorServiceData()
	if err != nil {
		return errors.Wrapf(err, "failed getting release monitor service mapping data")
	}

	packagesToUpdate := make(map[string]string)
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

	// let's work on a branch when updating package versions, so we can create a PR from that branch later
	ref, err := o.switchBranch(repo)
	if err != nil {
		return errors.Wrapf(err, "failed to switch to working git branch")
	}

	err = o.updatePackagesGitRepository(repo, packagesToUpdate, tempDir)
	if err != nil {
		return errors.Wrapf(err, "failed to make updates on %s", o.RepoURI)
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return errors.Wrapf(err, "failed to get git worktree")
	}

	_, err = worktree.Commit("Wolfi update packages", &git.CommitOptions{})
	if err != nil {
		return errors.Wrapf(err, "failed to git commit")
	}

	if !o.DryRun {
		pushOpts := &git.PushOptions{RemoteName: "origin"}
		gitToken := os.Getenv("GITHUB_TOKEN")
		if gitToken != "" {
			pushOpts.Auth = &gitHttp.BasicAuth{
				Username: "abc123",
				Password: gitToken,
			}
		}

		err = repo.Push(pushOpts)
		if err != nil {
			return errors.Wrapf(err, "failed to git push")
		}

		// create a pull request
		return o.createPullRequest(repo, ref)

	}

	return nil
}

func (o Options) updatePackagesGitRepository(repo *git.Repository, packagesToUpdate map[string]string, tempDir string) error {

	// bump packages that need updating
	for packageName, latestVersion := range packagesToUpdate {

		// if new versions are available lets bump the packages in the target melange git repo
		//if o.Batch {
		configFile := filepath.Join(tempDir, packageName+".yaml")

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
	// optionally, resize scanner's capacity for lines over 64K, see next example
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, packageName) {
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
	name := time.Now().Format("2006102150405")

	worktree, err := repo.Worktree()
	if err != nil {
		return "", errors.Wrapf(err, "failed to get git worktree")
	}
	ref := plumbing.ReferenceName("refs/heads/wolfictl-" + name)
	err = worktree.Checkout(&git.CheckoutOptions{
		Create: true,
		Branch: ref,
	})
	return ref, err
}

func (o Options) getPackageConfigs(tempDir string) error {
	var err error
	if o.PackageName != "" {
		// get a single package
		filename := filepath.Join(tempDir, o.PackageName+".yaml")
		err = o.readPackageConfig(filename)
		if err != nil {
			return errors.Wrapf(err, "failed to read package config %s", filename)
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

func (o Options) createPullRequest(repo *git.Repository, ref plumbing.ReferenceName) error {
	remote, err := repo.Remote("origin")
	if err != nil {
		return errors.Wrapf(err, "failed to find git origin URL")
	}
	if len(remote.Config().URLs) == 0 {
		return fmt.Errorf("no remote config URLs found for remote origin")
	}

	owner, repoName, err := parseGitURL(remote.Config().URLs[0])
	if err != nil {
		return errors.Wrapf(err, "failed to find git origin URL")
	}

	client := github.NewClient(o.GitHubHTTPClient)

	pr, _, err := client.PullRequests.Create(context.Background(), owner, repoName, &github.NewPullRequest{
		Title: github.String(o.PullRequestTitle),
		Head:  github.String(ref.String()),
		Base:  github.String(o.PullRequestBaseBranch),
		Body:  github.String(wolfiImage),
	})

	if err != nil {
		return errors.Wrapf(err, "failed to create pull request")
	}
	o.Logger.Printf("Pull Request Created: https://github.com/%s/%s/pull/%d", owner, repoName, *pr.Number)
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
