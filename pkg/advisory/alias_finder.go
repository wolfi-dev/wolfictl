package advisory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/samber/lo"
)

type AliasFinder interface {
	CVEForGHSA(ctx context.Context, ghsaID string) (string, error)
	GHSAsForCVE(ctx context.Context, cveID string) ([]string, error)
}

type HTTPAliasFinder struct {
	client          *http.Client
	ghToken         string
	cacheGHSAsByCVE map[string][]string
	cacheCVEByGHSA  map[string]string
}

// TODO: Allow providing a standard GitHub client that has taken care of its own
//  auth.

func NewHTTPAliasFinderWithToken(client *http.Client, ghToken string) *HTTPAliasFinder {
	return &HTTPAliasFinder{
		ghToken:         ghToken,
		client:          client,
		cacheGHSAsByCVE: make(map[string][]string),
		cacheCVEByGHSA:  make(map[string]string),
	}
}

func NewHTTPAliasFinder(client *http.Client) *HTTPAliasFinder {
	return NewHTTPAliasFinderWithToken(client, "")
}

func (f *HTTPAliasFinder) CVEForGHSA(ctx context.Context, ghsaID string) (string, error) {
	// Check cache first
	if cveID, ok := f.cacheCVEByGHSA[ghsaID]; ok {
		return cveID, nil
	}

	requestPath := fmt.Sprintf("/advisories/%s", url.PathEscape(ghsaID))
	respBody, err := f.gitHubAPIGet(ctx, requestPath, nil)
	if err != nil {
		return "", err
	}
	defer respBody.Close()

	var ghsa githubSecurityAdvisoryResponse
	if err := json.NewDecoder(respBody).Decode(&ghsa); err != nil {
		return "", err
	}

	// Update cache
	f.cacheCVEByGHSA[ghsaID] = ghsa.CVEID

	return ghsa.CVEID, nil
}

func (f *HTTPAliasFinder) GHSAsForCVE(ctx context.Context, cveID string) ([]string, error) {
	// Check cache first
	if ghsaIDs, ok := f.cacheGHSAsByCVE[cveID]; ok {
		return ghsaIDs, nil
	}

	respBody, err := f.gitHubAPIGet(
		ctx,
		"/advisories",
		map[string]string{"cve_id": cveID},
	)
	if err != nil {
		return nil, err
	}
	defer respBody.Close()

	var ghsas []githubSecurityAdvisoryResponse
	if err := json.NewDecoder(respBody).Decode(&ghsas); err != nil {
		return nil, err
	}

	ghsaIDs := lo.Map(ghsas, func(ghsa githubSecurityAdvisoryResponse, _ int) string {
		return ghsa.GHSAID
	})

	// Update cache
	f.cacheGHSAsByCVE[cveID] = ghsaIDs

	return ghsaIDs, nil
}

func (f *HTTPAliasFinder) gitHubAPIGet(ctx context.Context, requestPath string, queryParameters map[string]string) (io.ReadCloser, error) {
	u, err := url.Parse("https://api.github.com")
	if err != nil {
		return nil, err
	}
	u.Path = requestPath
	if queryParameters != nil {
		q := u.Query()
		for k, v := range queryParameters {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header = http.Header{
		"Accept":               []string{"application/vnd.github+json"},
		"X-GitHub-Api-Version": []string{"2022-11-28"},
	}

	if f.ghToken == "" {
		if token := os.Getenv("GITHUB_TOKEN"); token != "" {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		}
	} else {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", f.ghToken))
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var msg []byte
		if resp.Body != nil {
			//nolint:errcheck // This is a best-effort attempt to read the body.
			msg, _ = io.ReadAll(resp.Body)
		}
		return nil, fmt.Errorf("unexpected status code %d, body: %s", resp.StatusCode, string(msg))
	}

	return resp.Body, nil
}

type githubSecurityAdvisoryResponse struct {
	ID                    int    `json:"id"`
	GHSAID                string `json:"ghsa_id"`
	CVEID                 string `json:"cve_id"`
	URL                   string `json:"url"`
	HTMLURL               string `json:"html_url"`
	RepositoryAdvisoryURL string `json:"repository_advisory_url"`
	Summary               string `json:"summary"`
	Description           string `json:"description"`
	Type                  string `json:"type"`
	Severity              string `json:"severity"`
	SourceCodeLocation    string `json:"source_code_location"`
	Identifiers           []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifiers"`
	References       []string    `json:"references"`
	PublishedAt      time.Time   `json:"published_at"`
	UpdatedAt        time.Time   `json:"updated_at"`
	GitHubReviewedAt time.Time   `json:"github_reviewed_at"`
	NVDPublishedAt   time.Time   `json:"nvd_published_at"`
	WithdrawnAt      interface{} `json:"withdrawn_at"`
	Vulnerabilities  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		FirstPatchedVersion    string   `json:"first_patched_version"`
		VulnerableVersionRange string   `json:"vulnerable_version_range"`
		VulnerableFunctions    []string `json:"vulnerable_functions"`
	} `json:"vulnerabilities"`
	CVSS struct {
		VectorString string  `json:"vector_string"`
		Score        float64 `json:"score"`
	} `json:"cvss"`
	CWEs []struct {
		CWEID string `json:"cwe_id"`
		Name  string `json:"name"`
	} `json:"cwes"`
	Credits []struct {
		User struct {
			Login             string `json:"login"`
			ID                int    `json:"id"`
			NodeID            string `json:"node_id"`
			AvatarURL         string `json:"avatar_url"`
			GravatarID        string `json:"gravatar_id"`
			URL               string `json:"url"`
			HTMLURL           string `json:"html_url"`
			FollowersURL      string `json:"followers_url"`
			FollowingURL      string `json:"following_url"`
			GistsURL          string `json:"gists_url"`
			StarredURL        string `json:"starred_url"`
			SubscriptionsURL  string `json:"subscriptions_url"`
			OrganizationsURL  string `json:"organizations_url"`
			ReposURL          string `json:"repos_url"`
			EventsURL         string `json:"events_url"`
			ReceivedEventsURL string `json:"received_events_url"`
			Type              string `json:"type"`
			SiteAdmin         bool   `json:"site_admin"`
		} `json:"user"`
		Type string `json:"type"`
	} `json:"credits"`
}
