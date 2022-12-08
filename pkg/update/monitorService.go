package update

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

type MonitorService struct {
	Client        *RLHTTPClient
	Logger        *log.Logger
	DataMapperURL string
}

type Row struct {
	Identifier  string
	ServiceName string
}

type ReleaseMonitorVersions struct {
	LatestVersion  string   `json:"latest_version"`
	StableVersions []string `json:"stable_versions"`
}
type MonitorServiceName int

const releaseMonitorURL = "https://release-monitoring.org/api/v2/versions/?project_id=%s"

func (m MonitorService) getMonitorServiceData() (map[string]Row, error) {

	req, _ := http.NewRequest("GET", m.DataMapperURL, nil)
	resp, err := m.Client.Do(req)

	if err != nil {
		return nil, errors.Wrapf(err, "failed getting URI %s", m.DataMapperURL)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non ok http response for URI %s code: %v", m.DataMapperURL, resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "reading monitor service mapper data file")
	}
	return m.parseData(string(b))
}

func (m MonitorService) parseData(rawdata string) (map[string]Row, error) {

	data := make(map[string]Row)

	lines := strings.Split(rawdata, "\n")
	// start from index 2 as we want to skip the first two lines
	for i := 2; i < len(lines); i++ {
		line := lines[i]
		parts := strings.Split(line, "|")
		if len(parts) != 6 {
			m.Logger.Printf("found %d parts, expected 6 in line %s", len(parts), line)
			continue
		}

		// if notes say to skip then lets not include this row in the update checks
		notes := strings.TrimSpace(parts[4])
		if strings.HasPrefix(notes, "SKIP") {
			continue
		}

		data[parts[1]] = Row{
			Identifier:  parts[2],
			ServiceName: parts[3],
		}
	}

	return data, nil

}

func (m MonitorService) getLatestReleaseVersion(identifier string, name string) (string, error) {
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
