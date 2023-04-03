package update

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/fatih/color"

	http2 "github.com/wolfi-dev/wolfictl/pkg/http"

	"github.com/wolfi-dev/wolfictl/pkg/melange"

	version "github.com/wolfi-dev/wolfictl/pkg/versions"

	"github.com/pkg/errors"
)

type MonitorService struct {
	Client           *http2.RLHTTPClient
	GitHubHTTPClient *http2.RLHTTPClient
	Logger           *log.Logger
	DataMapperURL    string
}

type ReleaseMonitorVersions struct {
	LatestVersion  string   `json:"latest_version"`
	StableVersions []string `json:"stable_versions"`
}
type MonitorServiceName int

const (
	releaseMonitorURL = "https://release-monitoring.org/api/v2/versions/?project_id=%d"
)

func (m MonitorService) getLatestReleaseMonitorVersions(melangePackages map[string]*melange.Packages) (packagesToUpdate map[string]NewVersionResults, errorMessages map[string]string) {
	packagesToUpdate = make(map[string]NewVersionResults)
	errorMessages = make(map[string]string)

	// iterate packages from the target git repo and check if a new version is available
	for i := range melangePackages {
		p := melangePackages[i]
		rm := p.Config.Update.ReleaseMonitor
		if rm == nil {
			continue
		}

		latestVersion, err := m.getLatestReleaseVersion(rm.Identifier)
		if err != nil {
			errorMessages[p.Config.Package.Name] = fmt.Sprintf(
				"failed getting latest release version for package %s, identifier %d: %s",
				p.Config.Package.Name, rm.Identifier, err.Error(),
			)
		}

		// replace any nonstandard version separators
		if p.Config.Update.VersionSeparator != "" {
			latestVersion = strings.ReplaceAll(latestVersion, p.Config.Update.VersionSeparator, ".")
		}

		currentVersionSemver, err := version.NewVersion(p.Config.Package.Version)
		if err != nil {
			errorMessages[p.Config.Package.Name] = fmt.Sprintf(
				"failed to create a version from package %s: %s.  Error: %s",
				p.Config.Package.Name, p.Config.Package.Version, err,
			)
			continue
		}

		latestVersionSemver, err := version.NewVersion(latestVersion)
		if err != nil {
			errorMessages[p.Config.Package.Name] = color.GreenString(fmt.Sprintf(
				"failed to create a latestVersion from package %s: %s.  Error: %s",
				p.Config.Package.Name, latestVersion, err,
			))
			continue
		}

		if currentVersionSemver.Equal(latestVersionSemver) {
			m.Logger.Printf(
				"%s is on the latest version %s",
				p.Config.Package.Name, latestVersionSemver.Original(),
			)
		}

		if currentVersionSemver.LessThan(latestVersionSemver) {
			m.Logger.Printf(
				"there is a new stable version available %s, current wolfi version %s, new %s",
				p.Config.Package.Name, p.Config.Package.Version, latestVersion,
			)
			packagesToUpdate[p.Config.Package.Name] = NewVersionResults{Version: latestVersionSemver.Original()}
		}
	}
	return packagesToUpdate, errorMessages
}

func (m MonitorService) getLatestReleaseVersion(identifier int) (string, error) {
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
