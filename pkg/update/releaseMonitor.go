package update

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"

	http2 "github.com/wolfi-dev/wolfictl/pkg/http"

	"github.com/wolfi-dev/wolfictl/pkg/melange"

	version "github.com/wolfi-dev/wolfictl/pkg/versions"
)

type MonitorService struct {
	Client        *http2.RLHTTPClient
	Logger        *log.Logger
	DataMapperURL string
}

type ReleaseMonitorVersions struct {
	LatestVersion  string   `json:"latest_version"`
	StableVersions []string `json:"stable_versions"`
}
type MonitorServiceName int

const (
	releaseMonitorURL = "https://release-monitoring.org/api/v2/versions/?project_id=%d"
)

type CustomTransport struct {
	Transport http.RoundTripper
	Token     string
}

func (t *CustomTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Token %s", t.Token))
	}
	return t.Transport.RoundTrip(req)
}

func (m MonitorService) getLatestReleaseMonitorVersions(melangePackages map[string]*melange.Packages) (packagesToUpdate map[string]NewVersionResults, errorMessages map[string]string) {
	packagesToUpdate = make(map[string]NewVersionResults)
	errorMessages = make(map[string]string)
	releaseMonitorPackages := make(map[string]*melange.Packages)

	// build a separate map of packages that use release monitor
	// not necessarily needed but helps with logging to know truly how many packages are left
	for packageName := range melangePackages {
		p := melangePackages[packageName]
		rm := p.Config.Update.ReleaseMonitor
		if rm != nil {
			releaseMonitorPackages[packageName] = p
		}
	}
	size := len(releaseMonitorPackages)
	count := 0

	// iterate packages from the target git repo and check if a new version is available
ReleaseMonitorPackagesLoop:
	for packageName := range releaseMonitorPackages {
		count++
		p := releaseMonitorPackages[packageName]
		rm := releaseMonitorPackages[packageName].Config.Update.ReleaseMonitor

		m.Logger.Printf("[%d/%d] %s: checking release monitor using id %d\n", count, size, packageName, rm.Identifier)

		latestVersion, err := m.getLatestReleaseVersion(rm.Identifier)
		if err != nil {
			errorMessages[p.Config.Package.Name] = fmt.Sprintf(
				"failed getting latest release version for package %s, identifier %d: %s",
				p.Config.Package.Name, rm.Identifier, err.Error(),
			)
			continue
		}
		if latestVersion == "" {
			errorMessages[p.Config.Package.Name] = fmt.Sprintf(
				"no latest version found in release monitor for package %s, identifier %d",
				p.Config.Package.Name, rm.Identifier,
			)
			continue
		}

		// ignore versions that match a regex pattern in the melange update config
		if len(p.Config.Update.IgnoreRegexPatterns) > 0 {
			for _, pattern := range p.Config.Update.IgnoreRegexPatterns {
				regex, err := regexp.Compile(pattern)
				if err != nil {
					errorMessages[p.Config.Package.Name] = fmt.Sprintf("failed to compile regex %s", pattern)
					continue
				}
				// if we satify any of the regex patterns, then we ignore the version
				if regex.MatchString(latestVersion) {
					break ReleaseMonitorPackagesLoop
				}
			}
		}

		if p.Config.Update.FilterPrefix != "" {
			// if the version did not match the prefix then ignore it.
			if !strings.HasPrefix(latestVersion, p.Config.Update.FilterPrefix) {
				break ReleaseMonitorPackagesLoop
			}
		}

		// replace any nonstandard version separators
		if p.Config.Update.VersionSeparator != "" {
			latestVersion = strings.ReplaceAll(latestVersion, p.Config.Update.VersionSeparator, ".")
		}

		if p.Config.Update.ReleaseMonitor.StripPrefix != "" {
			latestVersion = strings.TrimPrefix(latestVersion, p.Config.Update.ReleaseMonitor.StripPrefix)
		}

		if p.Config.Update.ReleaseMonitor.StripSuffix != "" {
			latestVersion = strings.TrimSuffix(latestVersion, p.Config.Update.ReleaseMonitor.StripSuffix)
		}

		latestVersion, err = transformVersion(p.Config.Update, latestVersion)
		if err != nil {
			errorMessages[p.Config.Package.Name] = fmt.Sprintf(
				"failed to apply version transforms to %s for package %s.  Error: %s",
				latestVersion, p.Config.Package.Name, err,
			)
		}

		latestVersionSemver, err := version.NewVersion(latestVersion)
		if err != nil {
			errorMessages[p.Config.Package.Name] = fmt.Sprintf(
				"failed to create a latestVersion from package %s: %s.  Error: %s",
				p.Config.Package.Name, latestVersion, err,
			)
			continue
		}

		packagesToUpdate[p.Config.Package.Name] = NewVersionResults{Version: latestVersionSemver.Original()}
	}
	return packagesToUpdate, errorMessages
}

func (m MonitorService) getLatestReleaseVersion(identifier int) (string, error) {
	targetURL := fmt.Sprintf(releaseMonitorURL, identifier)
	var err error

	// Setup retry variables
	maxRetries := 3
	backoffFactor := 2.0
	initialBackoff := time.Second // 1 second

	for i := 0; i < maxRetries; i++ {
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			return "", fmt.Errorf("failed creating GET request %s: %w", targetURL, err)
		}

		resp, err := m.Client.Do(req)
		if err != nil {
			return "", fmt.Errorf("failed getting URI %s: %w", targetURL, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return "", fmt.Errorf("reading monitor service mapper data file: %w", err)
			}
			return m.parseVersions(b)
		}

		// Check if the status code is a 500 or 503, then retry
		if resp.StatusCode == http.StatusInternalServerError || resp.StatusCode == http.StatusServiceUnavailable {
			// Calculate the next backoff duration
			backoffDuration := time.Duration(math.Pow(backoffFactor, float64(i))) * initialBackoff
			time.Sleep(backoffDuration)
			continue // Retry
		}

		return "", fmt.Errorf("non ok http response for URI %s code: %v", targetURL, resp.StatusCode)
	}

	return "", fmt.Errorf("max retries reached; last error: %v", err)
}

func (m MonitorService) parseVersions(rawdata []byte) (string, error) {
	versions := ReleaseMonitorVersions{}
	err := json.Unmarshal(rawdata, &versions)
	if err != nil {
		return "", fmt.Errorf("unmarshalling version data: %w", err)
	}

	if len(versions.StableVersions) == 0 {
		return "", fmt.Errorf("no stable version found: %w", err)
	}
	return versions.StableVersions[0], nil
}
