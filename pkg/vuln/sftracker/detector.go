//nolint:gocritic // hugeParam and rangeValCopy not worth it here
package sftracker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"

	"github.com/wolfi-dev/wolfictl/pkg/vuln"
)

var _ vuln.Detector = (*SecfixesTracker)(nil)

type SecfixesTracker struct {
	baseURL string
	client  *http.Client
}

// NewDetector returns a new Secfixes Tracker client.
func NewDetector(baseURL string, httpClient *http.Client) *SecfixesTracker {
	return &SecfixesTracker{
		baseURL: baseURL,
		client:  httpClient,
	}
}

func (s *SecfixesTracker) VulnerabilitiesForPackages(_ context.Context, _ ...string) (map[string][]vuln.Match, error) {
	// TODO: either implement this method or delete the whole SecfixesTracker type.
	panic("implement me")
}

func (s *SecfixesTracker) VulnerabilitiesForPackage(_ context.Context, name string) ([]vuln.Match, error) {
	wrapErr := func(err error) error {
		return fmt.Errorf("unable to get vulnerabilities for package %q: %w", name, err)
	}

	pkg, err := s.getPackage(name)
	if err != nil {
		return nil, wrapErr(err)
	}

	cpeMatches := pkg.CPEMatch
	result := make([]vuln.Match, 0, len(cpeMatches))

	for _, m := range cpeMatches {
		match, err := parseMatch(m)
		if err != nil {
			return nil, wrapErr(err)
		}
		result = append(result, match)
	}

	return result, nil
}

func (s *SecfixesTracker) AllVulnerabilities(_ context.Context) (map[string][]vuln.Match, error) {
	wrapErr := func(err error) error {
		return fmt.Errorf("unable to get vulnerabilities for distro: %w", err)
	}

	branch, err := s.getBranch("wolfi-os")
	if err != nil {
		return nil, err
	}

	result := make(map[string][]vuln.Match)
	for _, item := range branch.Items {
		for _, m := range item.CpeMatch {
			match, err := parseMatch(m)
			if err != nil {
				return nil, wrapErr(err)
			}

			result[match.Package.Name] = append(result[match.Package.Name], match)
		}
	}

	return result, nil
}

func (s *SecfixesTracker) getPackage(name string) (*packageResponse, error) {
	url := s.urlForPackage(name)
	readCloser, err := s.get(url)
	if err != nil {
		return nil, err
	}
	defer readCloser.Close()

	r := &packageResponse{}
	err = json.NewDecoder(readCloser).Decode(r)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func (s *SecfixesTracker) getBranch(name string) (*branchResponse, error) {
	url := s.urlForBranch(name)
	readCloser, err := s.get(url)
	if err != nil {
		return nil, err
	}
	defer readCloser.Close()

	r := &branchResponse{}
	err = json.NewDecoder(readCloser).Decode(r)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func (s *SecfixesTracker) get(url string) (io.ReadCloser, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept", "application/json")

	response, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != 200 {
		response.Body.Close()
		return nil, fmt.Errorf("unexpected response status %q for GET %q", response.Status, url)
	}

	return response.Body, nil
}

func (s *SecfixesTracker) urlForPackage(name string) string {
	return "https://" + path.Join(s.baseURL, "srcpkg", name)
}

func (s *SecfixesTracker) urlForBranch(name string) string {
	return "https://" + path.Join(s.baseURL, "branch", name)
}

type packageResponse struct {
	CPEMatch []cpeMatch `json:"cpeMatch"`
}

//nolint:revive,stylecheck // we don't have control over JSON fields here
type cpeMatch struct {
	Context          string `json:"@context"`
	CPEUri           string `json:"cpeUri"`
	Id               string `json:"id"`
	MaximumVersion   string `json:"maximumVersion"`
	MaximumVersionOp string `json:"maximumVersionOp"`
	MinimumVersion   string `json:"minimumVersion"`
	MinimumVersionOp string `json:"minimumVersionOp"`
	Package          string `json:"package"`
	Type             string `json:"type"`
	Vuln             string `json:"vuln"`
}

func parseMatch(m cpeMatch) (vuln.Match, error) {
	vr, err := parseVersionRange(m)
	if err != nil {
		return vuln.Match{}, err
	}

	match := vuln.Match{
		Package: vuln.Package{
			Name: path.Base(m.Package),
		},
		CPE: vuln.CPE{
			URI:          m.CPEUri,
			VersionRange: vr,
		},
		Vulnerability: vuln.Vulnerability{
			ID:  path.Base(m.Vuln),
			URL: m.Vuln,
		},
	}

	return match, nil
}

func parseVersionRange(match cpeMatch) (vuln.VersionRange, error) {
	if match.MaximumVersionOp == "==" && match.MaximumVersion != "" {
		return vuln.VersionRange{SingleVersion: match.MaximumVersion}, nil
	}

	r := vuln.VersionRange{
		VersionRangeLower: match.MinimumVersionOp,
		VersionRangeUpper: match.MaximumVersion,
	}

	switch op := match.MinimumVersionOp; op {
	case ">":
		r.VersionRangeLowerInclusive = false
	case ">=":
		r.VersionRangeLowerInclusive = true
	default:
		return vuln.VersionRange{}, fmt.Errorf("unable to parse version range: invalid MinimumVersionOp value %q", op)
	}

	switch op := match.MaximumVersionOp; op {
	case "<":
		r.VersionRangeUpperInclusive = false
	case "<=":
		r.VersionRangeUpperInclusive = true
	default:
		return vuln.VersionRange{}, fmt.Errorf("unable to parse version range: invalid MaximumVersionOp value %q", op)
	}

	return r, nil
}

//nolint:revive,stylecheck // we don't have control over JSON fields here
type branchResponse struct {
	Context string `json:"@context"`
	Id      string `json:"id"`
	Items   []struct {
		Context  string     `json:"@context"`
		CpeMatch []cpeMatch `json:"cpeMatch"`
		Cvss3    struct {
			Score  float64 `json:"score"`
			Vector string  `json:"vector"`
		} `json:"cvss3"`
		Description string `json:"description"`
		Id          string `json:"id"`
		Ref         []struct {
			Context       string `json:"@context"`
			Id            string `json:"id"`
			ReferenceType string `json:"referenceType"`
			Rel           string `json:"rel"`
			Type          string `json:"type"`
		} `json:"ref"`
		State []struct {
			Context        string `json:"@context"`
			Fixed          bool   `json:"fixed"`
			Id             string `json:"id"`
			PackageVersion string `json:"packageVersion"`
			Type           string `json:"type"`
			Vuln           string `json:"vuln"`
		} `json:"state"`
		Type string `json:"type"`
	} `json:"items"`
	Type string `json:"type"`
}
