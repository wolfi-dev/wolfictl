package update

import (
	"fmt"
	"os"
	"path/filepath"

	"chainguard.dev/melange/pkg/build"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

type MelageConfig struct {
	Package  build.Package    `yaml:"package"`
	Pipeline []build.Pipeline `yaml:"pipeline,omitempty"`
}

func (c Context) readAllPackagesFromRepo(tempDir string) error {
	var fileList []string

	err := filepath.Walk(tempDir, func(path string, fi os.FileInfo, err error) error {
		// skip if the path is not the root folder of the melange config repo
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

	fmt.Printf("found %[1]d packages\n", len(fileList))

	for _, fi := range fileList {
		fmt.Printf("reading packages %s \n", fi)
		err = c.readPackageConfig(fi)
		if err != nil {
			return errors.Wrapf(err, "failed to read package config %s", fi)
		}
	}
	return nil
}

// read a single melange config using the package name to match the filename
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
