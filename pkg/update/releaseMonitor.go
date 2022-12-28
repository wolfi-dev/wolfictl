package update

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"chainguard.dev/melange/pkg/build"

	"github.com/hashicorp/go-version"

	"github.com/pkg/errors"
)

type MonitorService struct {
	Client           *RLHTTPClient
	GitHubHTTPClient *RLHTTPClient
	Logger           *log.Logger
	DataMapperURL    string
}

type ReleaseMonitorVersions struct {
	LatestVersion  string   `json:"latest_version"`
	StableVersions []string `json:"stable_versions"`
}
type MonitorServiceName int

const (
	releaseMonitorURL = "https://release-monitoring.org/api/v2/versions/?project_id=%s"
	releaseMonitor    = "RELEASE_MONITOR"
)

func (m MonitorService) getLatestReleaseMonitorVersions(
	mapperData map[string]Row, melangePackages map[string]build.Configuration,
) (packagesToUpdate map[string]string, errorMessages []string, err error) {
	packagesToUpdate = make(map[string]string)

	// iterate packages from the target git repo and check if a new version is available
	for i := range melangePackages {
		item := mapperData[melangePackages[i].Package.Name]
		if item.Identifier == "" {
			continue
		}
		if item.ServiceName != releaseMonitor {
			continue
		}

		latestVersion, err := m.getLatestReleaseVersion(item.Identifier)
		if err != nil {
			return nil, errorMessages, fmt.Errorf(
				"failed getting latest release version for package %s, identifier %s: %w",
				melangePackages[i].Package.Name, item.Identifier, err,
			)
		}

		currentVersionSemver, err := version.NewVersion(melangePackages[i].Package.Version)
		if err != nil {
			errorMessages = append(errorMessages, fmt.Sprintf(
				"failed to create a version from package %s: %s.  Error: %s",
				melangePackages[i].Package.Name, melangePackages[i].Package.Version, err,
			))
			continue
		}

		latestVersionSemver, err := version.NewVersion(latestVersion)
		if err != nil {
			errorMessages = append(errorMessages, fmt.Sprintf(
				"failed to create a latestVersion from package %s: %s.  Error: %s",
				melangePackages[i].Package.Name, latestVersion, err,
			))
			continue
		}

		if currentVersionSemver.LessThan(latestVersionSemver) {
			m.Logger.Printf(
				"there is a new stable version available %s, current wolfi version %s, new %s",
				melangePackages[i].Package.Name, melangePackages[i].Package.Version, latestVersion,
			)
			packagesToUpdate[melangePackages[i].Package.Name] = latestVersion
		}
	}
	return packagesToUpdate, errorMessages, nil
}

func (m MonitorService) getLatestReleaseVersion(identifier string) (string, error) {
	targetURL := fmt.Sprintf(releaseMonitorURL, identifier)
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return "", errors.Wrapf(err, "failed creating GET request %s", targetURL)
	}

	resp, err := m.Client.Do(req)
	if err != nil {
		return "", errors.Wrapf(err, "failed getting URI %s", targetURL)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("non ok http response for URI %s code: %v", targetURL, resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "reading monitor service mapper data file")
	}
	return m.parseVersions(b)
}

func (m MonitorService) parseVersions(rawdata []byte) (string, error) {
	versions := ReleaseMonitorVersions{}
	err := json.Unmarshal(rawdata, &versions)
	if err != nil {
		return "", errors.Wrap(err, "unmarshalling version data")
	}

	if len(versions.StableVersions) == 0 {
		return "", errors.Wrap(err, "no stable version found")
	}
	return versions.StableVersions[0], nil
}
