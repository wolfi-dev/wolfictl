package update

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	gotemplate "text/template"

	"golang.org/x/exp/maps"

	"chainguard.dev/melange/pkg/config"

	"github.com/hashicorp/go-version"
	http2 "github.com/wolfi-dev/wolfictl/pkg/http"

	"github.com/wolfi-dev/wolfictl/pkg/melange"
	wolfiversions "github.com/wolfi-dev/wolfictl/pkg/versions"
)

/*
The graphql query used is the equivalent contained in this comment, which can be tested using GitHub's graphql explorer
https://docs.github.com/en/graphql/overview/explorer

Using a go template we can build a single query in batches of 100 that request the tags of many GitHub repos.

Querying Tags and Releases differ because with tags we need to pass an extra Query to filter on names that we are interested in
*/
var queryTags = `
query {
{{ range  $index, $r := .RepoList }}
  r{{$r.PackageName}}: repository(owner: "{{$r.Owner}}", name: "{{$r.Name}}") {
    nameWithOwner
    refs(refPrefix: "refs/tags/", query: "{{.Filter}}", orderBy: {field: TAG_COMMIT_DATE, direction: DESC}, first: 50) {
      totalCount
      nodes {
        name
        target {
          commitUrl
        }
      }
    }
  }{{ if not $index }}, {{end}}
{{ end }}
}
`

// some git repos do not use the "latest" github release well
// i.e. they perform a maintenance release of an old version but it can be marked as latest,
// 1.2.3.4 gets released but marked as latest while 1.3.0 exists which is the version we want to check against
// so we need to check previous number of versions to ensure we can locate the real latest release version
// for this reason we get the first 40 results in the query below
var queryReleases = `
query {
{{ range $index, $r := .RepoList }}
  r{{$r.PackageName}}: repository(owner: "{{$r.Owner}}", name: "{{$r.Name}}") {
    owner {
      login
    }
    name
    nameWithOwner
    releases(first: 20) {
      totalCount
      nodes {
        tag {
          name
          target {
            commitUrl
          }
        }
        name
        isPrerelease
        isDraft
        isLatest
      }
    }
  }{{ if not $index }}, {{end}}
{{ end }}
}
`

type QueryTagsData struct {
	RepoList []RepoQuery
}
type QueryReleaseData struct {
	RepoList []RepoQuery
}
type RepoQuery struct {
	Owner       string
	Name        string
	Filter      string
	PackageName string
}

type ResponseError struct {
	Errors []struct {
		Type       string   `json:"type"`
		Path       []string `json:"path"`
		Extensions struct {
			SamlFailure bool `json:"saml_failure"`
		} `json:"extensions"`
		Locations []struct {
			Line   int `json:"line"`
			Column int `json:"column"`
		} `json:"locations"`
		Message string `json:"message"`
	} `json:"errors"`
}

type Repo struct {
	NameWithOwner string `json:"nameWithOwner"`
	Refs          struct {
		TotalCount int `json:"totalCount"`
		Nodes      []struct {
			TagName string `json:"name"`
			Target  struct {
				CommitURL string `json:"commitUrl"`
			} `json:"target"`
		} `json:"nodes"`
	} `json:"refs"`
}

type Releases struct {
	RepositoryCount int `json:"repositoryCount"`
	Owner           struct {
		Login string `json:"login"`
	} `json:"owner"`
	Name          string `json:"name"`
	NameWithOwner string `json:"nameWithOwner"`
	Releases      struct {
		TotalCount int `json:"totalCount"`
		Nodes      []struct {
			Tag struct {
				Name   string `json:"name"`
				Target struct {
					CommitURL string `json:"commitUrl"`
				} `json:"target"`
			} `json:"tag"`
			Name         string `json:"name"`
			IsPrerelease bool   `json:"isPrerelease"`
			IsDraft      bool   `json:"isDraft"`
			IsLatest     bool   `json:"isLatest"`
		} `json:"nodes"`
	} `json:"releases"`
}

type QueryTagsResponse struct {
	Data map[string]Repo `json:"data"`
}

type QueryReleasesResponse struct {
	Data map[string]Releases `json:"data"`
}

func NewGitHubReleaseOptions(packageConfigs map[string]*melange.Packages, ghClient *http2.RLHTTPClient) GitHubReleaseOptions {
	configsByHash := make(map[string]config.Configuration)

	// maintain a map of melange build configs for easy lookup when we get a response back from GitHub
	for _, pc := range packageConfigs {
		h256 := sha256.New()
		h256.Write([]byte(pc.Config.Package.Name))
		hash := fmt.Sprintf("%x", h256.Sum(nil))
		pc.Hash = hash
		configsByHash[pc.Hash] = pc.Config
	}

	o := GitHubReleaseOptions{
		Logger:           log.New(log.Writer(), "wolfictl update: ", log.LstdFlags|log.Lmsgprefix),
		PackageConfigs:   packageConfigs,
		ConfigsByHash:    configsByHash,
		GitHubHTTPClient: ghClient,
		ErrorMessages:    make(map[string]string),
	}

	return o
}

type GitHubReleaseOptions struct {
	GitHubHTTPClient *http2.RLHTTPClient
	Logger           *log.Logger
	PackageConfigs   map[string]*melange.Packages

	// hash is used to create graphql queries, maintain a map of associated configs
	ConfigsByHash map[string]config.Configuration
	ErrorMessages map[string]string
}

type RepoInfo struct {
	Owner       string
	Name        string
	Filter      string
	PackageName string
}

func (o GitHubReleaseOptions) getLatestGitHubVersions() (results map[string]NewVersionResults, errorMessages map[string]string, err error) {
	if len(o.PackageConfigs) == 0 {
		return nil, o.ErrorMessages, errors.New("no melange configs found")
	}

	releaseRepoList, tagRepoList := o.getRepoLists()

	results = make(map[string]NewVersionResults)

	if len(releaseRepoList) > 0 {
		results, err = o.getGitHubReleaseVersions(releaseRepoList)
		if err != nil {
			return results, o.ErrorMessages, err
		}
	}

	if len(tagRepoList) > 0 {
		tagResults, err := o.getGitHubTagVersions(tagRepoList)
		if err != nil {
			return results, o.ErrorMessages, err
		}
		maps.Copy(results, tagResults)
	}

	return results, o.ErrorMessages, err
}

func (o GitHubReleaseOptions) getRepoInfo(repoList map[string]string) ([]RepoInfo, error) {
	repos := []RepoInfo{}

	for packageName, ownerName := range repoList {
		pc, ok := o.PackageConfigs[packageName]
		if !ok {
			return nil, fmt.Errorf("no package config found for %s", packageName)
		}

		parts := strings.Split(ownerName, "/")
		if len(parts) != 2 {
			return nil, fmt.Errorf("malformed repo identifier should be in the form owner/repo, got %s", ownerName)
		}

		// if tag filter, filter-prefix or filter-contains is set then include this in the graphql query
		// this allows us to filter out any tags that do not match the filter.
		ghm := pc.Config.Update.GitHubMonitor
		var filter string

		switch {
		case ghm.TagFilterPrefix != "":
			filter = ghm.TagFilterPrefix
		case ghm.TagFilterContains != "":
			filter = ghm.TagFilterContains
		default:
			filter = ghm.TagFilter
		}

		repos = append(repos, RepoInfo{
			Owner:       parts[0],
			Name:        parts[1],
			Filter:      filter,
			PackageName: pc.Hash,
		})
	}

	return repos, nil
}

func (o GitHubReleaseOptions) getGitHubReleaseVersions(repoList map[string]string) (map[string]NewVersionResults, error) {
	repos, err := o.getRepoInfo(repoList)
	if err != nil {
		return nil, err
	}

	return o.getResultsFromTemplate(queryReleases, repos)
}

func (o GitHubReleaseOptions) getGitHubTagVersions(repoList map[string]string) (map[string]NewVersionResults, error) {
	repos, err := o.getRepoInfo(repoList)
	if err != nil {
		return nil, err
	}

	return o.getResultsFromTemplate(queryTags, repos)
}

func (o GitHubReleaseOptions) getResultsFromTemplate(templateType string, repos []RepoInfo) (map[string]NewVersionResults, error) {
	// batch the requests sent to graphql API else we can get a bad gateway error returned
	batchSize := 10
	results := make(map[string]NewVersionResults)

	for i := 0; i < len(repos); i += batchSize {
		end := i + batchSize
		if end > len(repos) {
			end = len(repos)
		}
		repoBatch := repos[i:end]

		requestData := map[string]interface{}{
			"RepoList": repoBatch,
		}
		requestQuery := template(templateType, requestData)

		b, err := o.get(requestQuery)
		if err != nil {
			return nil, err
		}

		var resp interface{}
		switch templateType {
		case queryReleases:
			resp = &QueryReleasesResponse{}
		case queryTags:
			resp = &QueryTagsResponse{}
		default:
			return nil, errors.New("unknown template type")
		}

		err = json.Unmarshal(b, resp)
		if err != nil {
			return nil, err
		}

		var batchResults map[string]NewVersionResults
		switch templateType {
		case queryReleases:
			batchResults, err = o.parseGitHubReleases(resp.(*QueryReleasesResponse))
		case queryTags:
			batchResults, err = o.parseGitHubTags(resp.(*QueryTagsResponse))
		default:
			return nil, errors.New("unknown template type")
		}

		if err != nil {
			return nil, fmt.Errorf("failed to parse results: %w", err)
		}

		// merge batchResults into results
		maps.Copy(results, batchResults)
	}

	if len(o.ErrorMessages) == 0 && len(results) == 0 {
		return nil, fmt.Errorf("no versions returned from github graphql api")
	}
	return results, nil
}

func (o GitHubReleaseOptions) get(requestQuery string) ([]byte, error) {
	payload := map[string]string{
		"query": requestQuery,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	o.Logger.Printf("request query, to check visit https://docs.github.com/en/graphql/overview/explorer: %s", requestQuery)

	req, err := http.NewRequest("POST", "https://api.github.com/graphql", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, errors.New("no GITHUB_TOKEN environment variable found, required by GitHub GraphQL API.  Create Personal Access Token without any scopes https://github.com/settings/tokens/new")
	}

	req.Header.Add("Authorization", fmt.Sprintf("bearer %s", token))
	resp, err := o.GitHubHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non ok http response for github graphql code: %s", resp.Status)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	e := ResponseError{}
	err = json.Unmarshal(b, &e)
	if err != nil {
		return nil, err
	}

	if len(e.Errors) > 0 {
		return b, fmt.Errorf("error response from github %s", e.Errors[0].Message)
	}
	return b, nil
}

// using the response from the GitHub GraphQL API, parse it and return a slice of latest package versions
func (o GitHubReleaseOptions) parseGitHubTags(repos *QueryTagsResponse) (results map[string]NewVersionResults, err error) {
	results = make(map[string]NewVersionResults)

	// for each repo queried, check for the latest version
	for packageNameHash, repo := range repos.Data {
		// strip prefix that avoids github thinking hash is not a float
		packageNameHash = strings.TrimPrefix(packageNameHash, "r")
		versions := make(map[string]string)
		c, ok := o.ConfigsByHash[packageNameHash]
		if !ok {
			return results, fmt.Errorf("no package config found for identifier %s", repo.NameWithOwner)
		}

		for _, node := range repo.Refs.Nodes {
			var commitSha string
			commitSha, err = getCommit(node.Target.CommitURL)
			if err != nil {
				return nil, fmt.Errorf("failed to get commit sha from commit URL %s: %w", node.Target.CommitURL, err)
			}

			v, err := o.prepareVersion(packageNameHash, node.TagName, repo.NameWithOwner)
			if err != nil {
				o.ErrorMessages[c.Package.Name] = err.Error()
				continue
			}
			if v == "" {
				continue
			}
			versions[v] = commitSha
		}
		err = o.getLatestVersion(packageNameHash, versions, repo.NameWithOwner, results)
		if err != nil {
			o.ErrorMessages[c.Package.Name] = err.Error()
		}
	}

	return results, nil
}

func (o GitHubReleaseOptions) parseGitHubReleases(repos *QueryReleasesResponse) (results map[string]NewVersionResults, err error) {
	results = make(map[string]NewVersionResults)

	for packageNameHash, node := range repos.Data {
		// strip prefix that avoids github thinking hash is not a float
		packageNameHash = strings.TrimPrefix(packageNameHash, "r")
		versions := make(map[string]string)

		// compare if this version is newer than the version we have in our
		// related melange package config
		c, ok := o.ConfigsByHash[packageNameHash]
		if !ok {
			return results, fmt.Errorf("failed to find %s in package configs", node.NameWithOwner)
		}

		// keep a map of original versions retrieved from github with a semver as the key so we can easily look it up after sorting
		for _, release := range node.Releases.Nodes {
			if release.IsDraft {
				continue
			}
			if release.IsPrerelease {
				continue
			}

			// first get the version from the release name but fall back to using the tag
			var commitSha string
			commitSha, err = getCommit(release.Tag.Target.CommitURL)
			if err != nil {
				return nil, fmt.Errorf("failed to get commit sha from commit URL %s: %w", release.Tag.Target.CommitURL, err)
			}

			tag := release.Tag.Name
			if tag == "" {
				o.ErrorMessages[c.Package.Name] = fmt.Sprintf("no tag found for release %s", node.Name)
				continue
			}

			// if tag filter matched the prefix then skip
			if !strings.HasPrefix(tag, c.Update.GitHubMonitor.TagFilter) {
				continue
			}

			v, err := o.prepareVersion(packageNameHash, tag, node.NameWithOwner)
			if err != nil {
				o.ErrorMessages[c.Package.Name] = err.Error()
				continue
			}
			if v == "" {
				continue
			}

			versions[v] = commitSha
		}

		err = o.getLatestVersion(packageNameHash, versions, node.NameWithOwner, results)
		if err != nil {
			o.ErrorMessages[c.Package.Name] = err.Error()
		}
	}

	return results, nil
}

func getCommit(commitURLStr string) (string, error) {
	commitURL, err := url.Parse(commitURLStr)
	if err != nil {
		return "", err
	}
	sha := path.Base(commitURL.Path)

	// Git SHA should be 40 hexadecimal chars
	r := regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

	if r.MatchString(sha) {
		return sha, nil
	}
	return "", fmt.Errorf("%s is not a sha", sha)
}

// createSemverSlice creates a slice of semver.Version pointers from the map of github results
func createSemverSlice(versionResults map[string]string) ([]*version.Version, error) {
	versions := []*version.Version{}
	for k := range versionResults {
		releaseVersionSemver, err := wolfiversions.NewVersion(k)
		if err != nil {
			return nil, fmt.Errorf("failed to create a version from %s: %w", k, err)
		}
		versions = append(versions, releaseVersionSemver)
	}
	return versions, nil
}

// findLatestVersion returns the latest semver.Version from the given slice.
func findLatestVersion(versions []*version.Version) *version.Version {
	sort.Sort(wolfiversions.ByLatest(versions))
	return versions[len(versions)-1]
}

func (o GitHubReleaseOptions) getLatestVersion(packageNameHash string, versionResults map[string]string, ownerName string, results map[string]NewVersionResults) error {
	versions, err := createSemverSlice(versionResults)
	if err != nil {
		return fmt.Errorf("failed to create a version slice for %s: %w", ownerName, err)
	}

	if len(versions) == 0 {
		return nil
	}

	latestVersionSemver := findLatestVersion(versions)

	c, ok := o.ConfigsByHash[packageNameHash]
	if !ok {
		return fmt.Errorf("failed to find %s in package configs", ownerName)
	}
	results[c.Package.Name] = NewVersionResults{Version: latestVersionSemver.Original(), Commit: versionResults[latestVersionSemver.Original()]}

	return nil
}

func shouldSkipVersion(v string) bool {
	invalid := []string{"alpha", "beta", "rc", "pre"}
	for _, i := range invalid {
		if strings.Contains(strings.ToLower(v), i) {
			return true
		}
	}
	return false
}

// function returns two slices, one for configs that use github releases and second that use tags
func (o GitHubReleaseOptions) getRepoLists() (releaseBatch, tagBatch map[string]string) {
	releaseRepoQuery := make(map[string]string)
	tagRepoQuery := make(map[string]string)

	for i := range o.PackageConfigs {
		c := o.PackageConfigs[i].Config
		if monitor := c.Update.GitHubMonitor; monitor != nil {
			identifier := monitor.Identifier
			if monitor.UseTags {
				tagRepoQuery[c.Package.Name] = identifier
			} else {
				releaseRepoQuery[c.Package.Name] = identifier
			}
		}
	}

	return releaseRepoQuery, tagRepoQuery
}

func (o GitHubReleaseOptions) prepareVersion(nameHash, v, id string) (string, error) {
	// strip any prefix chars using mapper data
	// the fastest way to check is to lookup git repo name in the map
	// data, but there's no guarantee the repo name and map data key are
	// the same if the identifiers don't match fall back to iterating
	// through all map data to match using identifier
	c, ok := o.ConfigsByHash[nameHash]
	if !ok {
		return "", fmt.Errorf("no melange package found for github response key / idendifier name %s", id)
	}
	ghm := c.Update.GitHubMonitor
	if ghm == nil {
		return "", fmt.Errorf("no github update config found for package %s", id)
	}

	// the github graphql query filter matches any occurrence, we want to make that more strict and remove any tags that do not START with the filter
	// deprecated: todo: ajayk remove this once we have migrated over to TagFilterPrefix
	if ghm.TagFilter != "" {
		if !strings.HasPrefix(v, ghm.TagFilter) {
			return "", nil
		}
	}
	// TagFilterPrefix replaces TagFilter so we can be explicit about what the filter does
	// TagFilterPrefix searches for prefix match only
	if ghm.TagFilterPrefix != "" {
		if !strings.HasPrefix(v, ghm.TagFilterPrefix) {
			return "", nil
		}
	}

	// TagFilterContains searches for substring match
	if ghm.TagFilterContains != "" {
		if !strings.Contains(v, ghm.TagFilterContains) {
			return "", nil
		}
	}

	if ghm.StripPrefix != "" {
		v = strings.TrimPrefix(v, ghm.StripPrefix)
	}

	if ghm.StripSuffix != "" {
		v = strings.TrimSuffix(v, ghm.StripSuffix)
	}

	ignore, err := ignoreVersions(c.Update.IgnoreRegexPatterns, v)
	if ignore {
		return "", err
	}

	if c.Update.VersionSeparator != "" {
		v = strings.ReplaceAll(v, c.Update.VersionSeparator, ".")
	}

	if shouldSkipVersion(v) {
		return "", nil
	}

	v, err = transformVersion(c.Update, v)
	if err != nil {
		return "", fmt.Errorf("failed to transform version %s: %w", v, err)
	}

	return v, nil
}

func ignoreVersions(patterns []string, v string) (bool, error) {
	// ignore versions that match a regex pattern in the melange update config
	if len(patterns) > 0 {
		for _, pattern := range patterns {
			regex, err := regexp.Compile(pattern)
			if err != nil {
				return true, fmt.Errorf("failed to compile regex %s: %w", pattern, err)
			}

			if regex.MatchString(v) {
				return true, nil
			}
		}
	}
	return false, nil
}

func template(tmpl string, data interface{}) string {
	var buf bytes.Buffer
	t := gotemplate.Must(gotemplate.New("").Parse(tmpl))
	t.Option("missingkey=error")
	if err := t.Execute(&buf, data); err != nil {
		log.Fatalf("Executing template: %v", err)
	}
	return buf.String()
}
