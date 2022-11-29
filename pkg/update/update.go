package update

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	gitHttp "github.com/go-git/go-git/v5/plumbing/transport/http"

	"github.com/go-git/go-git/v5/plumbing"

	"github.com/hashicorp/go-version"

	"github.com/go-git/go-git/v5"
	"github.com/pkg/errors"

	"golang.org/x/time/rate"
)

type Context struct {
	PackageName string
	RepoURI     string
	Batch       bool
	DryRun      bool
	Packages    map[string]MelageConfig
	Client      *RLHTTPClient
	Logger      *log.Logger
}

// New initialise including a map of existing wolfios packages
func New() (Context, error) {
	context := Context{

		Client: &RLHTTPClient{
			client: http.DefaultClient,

			// 1 request every (n) second(s) to avoid DOS'ing server
			Ratelimiter: rate.NewLimiter(rate.Every(2*time.Second), 1),
		},
		Logger: log.New(log.Writer(), "wupdater: ", log.LstdFlags|log.Lmsgprefix),
	}

	context.Packages = make(map[string]MelageConfig)

	return context, nil
}

func (c Context) Update() error {

	// clone the melange config git repo into a temp folder so we can work with it
	tempDir, err := os.MkdirTemp("", "wupdater")
	if err != nil {
		return errors.Wrapf(err, "failed to create temporary folder to clone package configs into")
	}
	if c.DryRun {
		c.Logger.Printf("using working directory %s", tempDir)
	} else {
		defer os.Remove(tempDir)
	}

	repo, err := git.PlainClone(tempDir, false, &git.CloneOptions{
		URL:      c.RepoURI,
		Progress: os.Stdout,
	})
	if err != nil {
		return errors.Wrapf(err, "failed to clone repository %s into %s", c.RepoURI, tempDir)
	}

	// first, let's get the package(s) we want to check for updates
	err = c.getPackageConfigs(tempDir)
	if err != nil {
		return errors.Wrapf(err, "failed to get package configs")
	}

	// second, check service for new package versions
	m := MonitorService{Client: c.Client, Logger: c.Logger}
	mapperData, err := m.getMonitorServiceData()
	if err != nil {
		return errors.Wrapf(err, "failed getting release monitor service mapping data")
	}

	packagesToUpdate := make(map[string]string)
	for _, config := range c.Packages {
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
			c.Logger.Printf("failed to create a version from package %s: %s.  Error: %s", config.Package.Name, config.Package.Version, err)
			continue
		}
		latestVersionSemver, err := version.NewVersion(latestVersion)
		if err != nil {
			c.Logger.Printf("failed to create a version from package %s: %s.  Error: %s", config.Package.Name, latestVersion, err)
			continue
		}

		if currentVersionSemver.LessThan(latestVersionSemver) {
			c.Logger.Printf("there is a new stable version available %s %s, current wolfi version %s", config.Package.Name, latestVersion, config.Package.Version)
			packagesToUpdate[config.Package.Name] = latestVersion
		}

	}

	err = c.updatePackagesGitRepository(repo, packagesToUpdate, tempDir)
	if err != nil {
		return errors.Wrapf(err, "failed to make updates on %s", c.RepoURI)
	}

	// diff any changes
	worktree, err := repo.Worktree()
	if err != nil {
		return errors.Wrapf(err, "failed to get git worktree")
	}

	_, err = worktree.Commit("Wolfi update packages", &git.CommitOptions{})
	if err != nil {
		return errors.Wrapf(err, "failed to git commit")
	}

	if !c.DryRun {
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
	}

	return nil
}

func (c Context) updatePackagesGitRepository(repo *git.Repository, packagesToUpdate map[string]string, tempDir string) error {
	// let's work on a branch when updating package versions, so we can create a PR from that branch later
	err := c.switchBranch(repo)
	if err != nil {
		return errors.Wrapf(err, "failed to switch to working git branch")
	}

	// bump packages that need updating
	for packageName, latestVersion := range packagesToUpdate {

		// if new versions are available lets bump the packages in the target melange git repo
		//if c.Batch {
		configFile := filepath.Join(tempDir, packageName+".yaml")

		err = c.bump(configFile, latestVersion)
		if err != nil {
			c.Logger.Printf("failed to bump config file %s to version %s: %s", configFile, latestVersion, err.Error())
		}
		worktree, err := repo.Worktree()
		if err != nil {
			return errors.Wrapf(err, "failed to get git worktree")
		}
		_, err = worktree.Add(packageName + ".yaml")
		if err != nil {
			return errors.Wrapf(err, "failed to get add %s", configFile)
		}
	}

	return nil
}

// create a unique branch
func (c Context) switchBranch(repo *git.Repository) error {
	name := time.Now().Format("2006102150405")

	worktree, err := repo.Worktree()
	if err != nil {
		return errors.Wrapf(err, "failed to get git worktree")
	}
	ref := plumbing.ReferenceName("refs/heads/wupdater-" + name)
	err = worktree.Checkout(&git.CheckoutOptions{
		Create: true,
		Branch: ref,
	})
	return err
}

func (c Context) getPackageConfigs(tempDir string) error {
	var err error
	if c.PackageName != "" {
		// get a single package
		filename := filepath.Join(tempDir, c.PackageName+".yaml")
		err = c.readPackageConfig(filename)
		if err != nil {
			return errors.Wrapf(err, "failed to read package config %s", filename)
		}
	} else {
		// get all packages in the provided git repo
		err = c.readAllPackagesFromRepo(tempDir)
		if err != nil {
			return errors.Wrapf(err, "failed to read package configs from repo %s", c.RepoURI)
		}
	}
	return nil
}
