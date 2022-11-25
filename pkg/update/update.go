package update

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

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

			// 1 request every second to avoid DOS'ing server
			Ratelimiter: rate.NewLimiter(rate.Every(1*time.Second), 1),
		},
		Logger: log.New(log.Writer(), "wupdater: ", log.LstdFlags|log.Lmsgprefix),
	}

	context.Packages = make(map[string]MelageConfig)

	//req, _ := http.NewRequest("GET", wolfios.WolfiosPackageRepository, nil)
	//resp, err := context.Client.Do(req)
	//
	//if err != nil {
	//	return context, errors.Wrapf(err, "failed getting URI %s", wolfios.WolfiosPackageRepository)
	//}
	//defer resp.Body.Close()
	//
	//if resp.StatusCode != http.StatusOK {
	//	return context, fmt.Errorf("non ok http response for URI %s code: %v", wolfios.WolfiosPackageRepository, resp.StatusCode)
	//}
	//
	//b, err := io.ReadAll(resp.Body)
	//if err != nil {
	//	return context, errors.Wrap(err, "reading APKBUILD file")
	//}

	// keep the map of wolfi packages on the main struct so it's easy to check if we already have any ABKBUILD dependencies
	//context.WolfiOSPackages, err = wolfios.ParseWolfiPackages(b)
	//if err != nil {
	//	return context, errors.Wrapf(err, "parsing wolfi packages")
	//}

	return context, nil
}

func (c Context) Update() error {

	tempDir, err := os.MkdirTemp("", "wupdater")
	if err != nil {
		return errors.Wrapf(err, "failed to create temporary folder to clone package configs into")
	}
	c.Logger.Printf("using temp dir %s", tempDir)
	//defer os.Remove(tempDir)

	_, err = git.PlainClone(tempDir, false, &git.CloneOptions{
		URL:      c.RepoURI,
		Progress: os.Stdout,
	})
	if err != nil {
		return errors.Wrapf(err, "failed to clone repository %s into %s", c.RepoURI, tempDir)
	}

	// first, let's get the package(s) we want to check for updates
	if c.PackageName != "" {
		filename := filepath.Join(tempDir, c.PackageName+".yaml")
		err = c.readPackageConfig(filename)
		if err != nil {
			return errors.Wrapf(err, "failed to read package config %s", filename)
		}
	} else {

		var fileList []string
		err := filepath.Walk(tempDir, func(path string, fi os.FileInfo, err error) error {
			c.Logger.Printf("path: %s", path)
			c.Logger.Printf("fi: %s", fi.Name())
			c.Logger.Printf("fi: %s", fi.Mode())
			if fi.IsDir() && path != tempDir {
				return filepath.SkipDir
			}
			if filepath.Ext(path) == ".yaml" {
				fileList = append(fileList, path)
			}

			return nil
		})

		if err != nil {
			return errors.Wrapf(err, "failed walking files in cloned directory %s", tempDir)
		}

		fmt.Printf("Found %[1]d packages.\n", len(fileList))

		for _, fi := range fileList {
			fmt.Printf("reading packages %s \n", fi)
			err = c.readPackageConfig(fi)
			if err != nil {
				return errors.Wrapf(err, "failed to read package config %s", fi)
			}
		}

	}
	for _, config := range c.Packages {
		c.Logger.Printf("found %s / %s", config.Package.Name, config.Package.Version)
	}
	// second, check service for new package versions

	// if new versions are available, create a pull request

	// if package name is empty let's get all packages from the git repo containing melange configs

	return nil
}

func (c Context) readPackageConfig(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return errors.Wrapf(err, "failed to read package config %s", filename)
	}

	packageConfig := MelageConfig{}

	err = yaml.Unmarshal(data, &packageConfig)
	if err != nil {
		return errors.Wrapf(err, "failed to unmarshal package data from filename %s", filename)
	}
	c.Packages[packageConfig.Package.Name] = packageConfig
	return nil
}
