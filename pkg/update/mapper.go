package update

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

type Row struct {
	PackageName     string
	Identifier      string
	ServiceName     string
	UseTags         bool
	Shared          bool
	TagFilter       string
	StripPrefixChar string
	StripSuffixChar string
}

func (o *Options) getMonitorServiceData() (map[string]Row, error) {
	req, err := http.NewRequest("GET", o.DataMapperURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request: %w", err)
	}
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

func (o *Options) parseData(rawdata string) (map[string]Row, error) {
	data := make(map[string]Row)

	lines := strings.Split(rawdata, "\n")
	// start from index 2 as we want to skip the first two lines
	for i := 2; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "|")

		// this is a breaking change (parts are now 11 not 7) however the mapping data is being moved directly into melange configs soon.  We are assuming that wolfictl update is only being used on wolfi itself, so we can make the corresponding mapping file change, that includes the extra fields until we move the data
		if len(parts) != 11 {
			return data, fmt.Errorf("found %d parts, expected 10 in line %s", len(parts), line)
		}

		// if notes say to skip then lets not include this row in the update checks
		notes := strings.TrimSpace(parts[9])
		if strings.HasPrefix(notes, "SKIP") {
			continue
		}

		useTags, err := strconv.ParseBool(strings.TrimSpace(parts[4]))
		if err != nil {
			useTags = false
		}
		shared, err := strconv.ParseBool(strings.TrimSpace(parts[5]))
		if err != nil {
			shared = false
		}

		data[strings.TrimSpace(parts[1])] = Row{
			PackageName:     strings.TrimSpace(parts[1]),
			Identifier:      strings.TrimSpace(parts[2]),
			ServiceName:     strings.TrimSpace(parts[3]),
			UseTags:         useTags,
			Shared:          shared,
			TagFilter:       strings.TrimSpace(parts[6]),
			StripPrefixChar: strings.TrimSpace(parts[7]),
			StripSuffixChar: strings.TrimSpace(parts[8]),
		}
	}

	return data, nil
}
