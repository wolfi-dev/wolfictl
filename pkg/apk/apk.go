package apk

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/chainguard-dev/go-apk/pkg/apk"
	"github.com/wolfi-dev/wolfictl/pkg/versions"

	"github.com/pkg/errors"
)

type Context struct {
	client   *http.Client
	indexURL string
}

func New(client *http.Client, indexURL string) Context {
	return Context{
		client:   client,
		indexURL: indexURL,
	}
}

func (c Context) GetApkPackages() (map[string]*apk.Package, error) {
	req, err := http.NewRequest("GET", c.indexURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "failed getting URI %s", c.indexURL)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non ok http response for URI %s code: %v", c.indexURL, resp.StatusCode)
	}

	return ParseApkIndex(resp.Body)
}

func ParseUnpackedApkIndex(indexData io.ReadCloser) (map[string]*apk.Package, error) {
	wolfiPackages := make(map[string]*apk.Package)

	packages, err := apk.ParsePackageIndex(indexData)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse response %v", indexData)
	}

	return getLatestPackagesMap(packages, wolfiPackages)
}

func getLatestPackagesMap(apkIndexPackages []*apk.Package, wolfiPackages map[string]*apk.Package) (map[string]*apk.Package, error) {
	for _, p := range apkIndexPackages {
		if wolfiPackages[p.Name] != nil {
			existingPackageVersion, err := versions.NewVersion(wolfiPackages[p.Name].Version)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to create a version for package %s from %s", p.Name, wolfiPackages[p.Name].Version)
			}

			apkPackageVersion, err := versions.NewVersion(p.Version)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to create a new version for package %s from %s", p.Name, p.Version)
			}

			// replace in our map if we find a newer version in the APKINDEX
			if existingPackageVersion.LessThan(apkPackageVersion) {
				wolfiPackages[p.Name] = p
			}
		} else {
			wolfiPackages[p.Name] = p
		}
	}
	log.Printf("found %d latest apk index package versions", len(wolfiPackages))
	return wolfiPackages, nil
}

func ParseApkIndex(indexData io.ReadCloser) (map[string]*apk.Package, error) {
	wolfiPackages := make(map[string]*apk.Package)

	apkIndex, err := apk.IndexFromArchive(indexData)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse response %v", indexData)
	}

	return getLatestPackagesMap(apkIndex.Packages, wolfiPackages)
}
