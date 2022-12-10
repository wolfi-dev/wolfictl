package update

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

type Row struct {
	Identifier  string
	ServiceName string
}

func (o Options) getMonitorServiceData() (map[string]Row, error) {

	req, _ := http.NewRequest("GET", o.DataMapperURL, nil)
	resp, err := o.Client.Do(req)

	if err != nil {
		return nil, errors.Wrapf(err, "failed getting URI %s", o.DataMapperURL)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non ok http response for URI %s code: %v", o.DataMapperURL, resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "reading monitor service mapper data file")
	}
	return o.parseData(string(b))
}

func (o Options) parseData(rawdata string) (map[string]Row, error) {

	data := make(map[string]Row)

	lines := strings.Split(rawdata, "\n")
	// start from index 2 as we want to skip the first two lines
	for i := 2; i < len(lines); i++ {
		line := lines[i]
		parts := strings.Split(line, "|")
		if len(parts) != 6 {
			o.Logger.Printf("found %d parts, expected 6 in line %s", len(parts), line)
			continue
		}

		// if notes say to skip then lets not include this row in the update checks
		notes := strings.TrimSpace(parts[4])
		if strings.HasPrefix(notes, "SKIP") {
			continue
		}

		data[strings.TrimSpace(parts[1])] = Row{
			Identifier:  strings.TrimSpace(parts[2]),
			ServiceName: strings.TrimSpace(parts[3]),
		}

	}

	return data, nil

}
