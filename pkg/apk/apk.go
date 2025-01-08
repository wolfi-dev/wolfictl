package apk

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"

	"github.com/hashicorp/go-retryablehttp"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/apk/auth"
	"github.com/wolfi-dev/wolfictl/pkg/versions"
)

type Context struct {
	client   *http.Client
	indexURL string
}

func New(client *http.Client, indexURL string) Context {
	rc := retryablehttp.NewClient()
	//	rc.Logger = log.New(io.Discard, "", 0) // Don't log requests at all.
	rc.HTTPClient = client
	return Context{
		client:   rc.StandardClient(),
		indexURL: indexURL,
	}
}

func (c Context) GetApkPackages() (map[string]*apk.Package, error) {
	req, err := http.NewRequest("GET", c.indexURL, nil)
	if err != nil {
		return nil, err
	}
	if err := auth.DefaultAuthenticators.AddAuth(context.Background(), req); err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed getting URI %s: %w", c.indexURL, err)
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
		return nil, fmt.Errorf("failed to parse response %v: %w", indexData, err)
	}

	return getLatestPackagesMap(packages, wolfiPackages)
}

func getLatestPackagesMap(apkIndexPackages []*apk.Package, wolfiPackages map[string]*apk.Package) (map[string]*apk.Package, error) {
	for _, p := range apkIndexPackages {
		if wolfiPackages[p.Name] != nil {
			vers := []string{wolfiPackages[p.Name].Version, p.Version}
			sort.Sort(versions.ByLatestStrings(vers))
			// replace in our map if we find a newer version in the APKINDEX
			if p.Version == vers[0] {
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
		return nil, fmt.Errorf("failed to parse response %v: %w", indexData, err)
	}

	return getLatestPackagesMap(apkIndex.Packages, wolfiPackages)
}
