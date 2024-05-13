package checks

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/wolfi-dev/wolfictl/pkg/tar"
)

// the wolfi package repo CI will write a file entry for every new .apk package that's been built
// in the form $ARCH|$PACKAGE_NAME|$VERSION_r$EPOCH
func getNewPackages(packageListFile string) (map[string]NewApkPackage, error) {
	rs := make(map[string]NewApkPackage)
	original, err := os.Open(packageListFile)
	if err != nil {
		return rs, fmt.Errorf("opening file %s: %w", packageListFile, err)
	}

	scanner := bufio.NewScanner(original)
	defer original.Close()
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		parts := strings.Split(scanner.Text(), "|")

		if len(parts) != 4 {
			return rs, fmt.Errorf("expected 3 parts but found %d when scanning %s", len(parts), scanner.Text())
		}
		versionParts := strings.Split(parts[3], "-")
		if len(versionParts) != 2 {
			return rs, fmt.Errorf("expected 2 version parts but found %d", len(versionParts))
		}

		arch := parts[0]
		packageName := parts[2]
		version := versionParts[0]

		epoch := versionParts[1]
		epoch = strings.TrimPrefix(epoch, "r")
		epoch = strings.TrimSuffix(epoch, ".apk")

		rs[packageName] = NewApkPackage{
			Version: version,
			Epoch:   epoch,
			Arch:    arch,
			Name:    packageName,
		}
	}

	return rs, nil
}

func downloadCurrentAPK(client *http.Client, apkIndexURL, newPackageName, dirCurrentApk string) error {
	apkURL := strings.ReplaceAll(apkIndexURL, "APKINDEX.tar.gz", newPackageName)
	resp, err := client.Get(apkURL)
	if err != nil {
		return fmt.Errorf("failed to get %s: %w", apkURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed for %s, status code: %d", apkURL, resp.StatusCode)
	}

	if err := tar.Untar(resp.Body, dirCurrentApk); err != nil {
		return fmt.Errorf("failed to untar new apk: %w", err)
	}
	return nil
}
