package update

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

type MonitorService struct {
	Client *RLHTTPClient
	Logger *log.Logger
}

type Row struct {
	Identifier  string
	ServiceName string
}
type MonitorServiceName int

const dataURL = "https://raw.githubusercontent.com/rawlingsj/wup-mapper/main/README.md"

func (m MonitorService) getMonitorServiceData() (map[string]Row, error) {

	req, _ := http.NewRequest("GET", dataURL, nil)
	resp, err := m.Client.Do(req)

	if err != nil {
		return nil, errors.Wrapf(err, "failed getting URI %s", dataURL)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non ok http response for URI %s code: %v", dataURL, resp.StatusCode)
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
			m.Logger.Printf("found %d parts, expected 4 in line %s", len(parts), line)
			continue
		}

		data[parts[1]] = Row{
			Identifier:  parts[2],
			ServiceName: parts[3],
		}
	}

	return data, nil

}

func (m MonitorService) getLatestReleaseVersion(identifier string) string {
	return ""
}
