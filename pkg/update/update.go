package update

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

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
			Ratelimiter: rate.NewLimiter(rate.Every(1*time.Second), 5),
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
	c.Logger.Printf("using temp dir %s", tempDir)
	defer os.Remove(tempDir)

	_, err = git.PlainClone(tempDir, false, &git.CloneOptions{
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
		//c.Logger.Printf("package %s, latest available version %s, current version %s", config.Package.Name, config.Package.Version, latestVersion)

		if currentVersionSemver.LessThan(latestVersionSemver) {
			c.Logger.Printf("there is a new stable version available %s %s, current wolfi version %s", config.Package.Name, latestVersion, config.Package.Version)
		}

		// if new versions are available, create a pull request
	}

	return nil
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
