package update

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	gotemplate "text/template"

	"chainguard.dev/melange/pkg/build"

	"github.com/fatih/color"

	"github.com/pkg/errors"

	"github.com/hashicorp/go-version"
	http2 "github.com/wolfi-dev/wolfictl/pkg/http"

	"github.com/wolfi-dev/wolfictl/pkg/melange"
	wolfiversions "github.com/wolfi-dev/wolfictl/pkg/versions"
	"golang.org/x/exp/maps"
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
    refs(refPrefix: "refs/tags/", query: "{{.Filter}}", orderBy: {field: TAG_COMMIT_DATE, direction: DESC}, last: 100) {
      totalCount
      nodes {
        name
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
    releases(first: 40) {
      totalCount
      nodes {
        tag {
          name
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
				Name string `json:"name"`
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
	configsByHash := make(map[string]build.Configuration)

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
	ConfigsByHash map[string]build.Configuration
	ErrorMessages map[string]string
}

func (o GitHubReleaseOptions) getLatestGitHubVersions() (results, errorMessages map[string]string, err error) {
	results = make(map[string]string)

	if len(o.PackageConfigs) == 0 {
		return results, o.ErrorMessages, errors.New("no melange configs found")
	}

	releaseRepoList, tagRepolist := o.getRepoLists()

	if len(releaseRepoList) > 0 {
		results, err = o.getGitHubReleaseVersions(releaseRepoList)
		if err != nil {
			return results, o.ErrorMessages, err
		}
	}

	if len(tagRepolist) > 0 {
		r, err := o.getGitHubTagVersions(tagRepolist)
		if err != nil {
			return results, o.ErrorMessages, err
		}

		// combine both release and tag versions from retrieved from GitHub
		maps.Copy(results, r)
	}

	return results, o.ErrorMessages, err
}

func (o GitHubReleaseOptions) getGitHubReleaseVersions(repoList map[string]string) (results map[string]string, err error) {
	results = make(map[string]string)
	queries := []RepoQuery{}

	for packageName, ownerName := range repoList {
		pc, ok := o.PackageConfigs[packageName]
		if !ok {
			return nil, fmt.Errorf("no package config found for %s", packageName)
		}

		parts := strings.Split(ownerName, "/")
		if len(parts) != 2 {
			return nil, fmt.Errorf("malformed repo identifier should be in the form owner/repo, got %s", ownerName)
		}

		queries = append(queries, RepoQuery{
			Owner:       parts[0],
			Name:        parts[1],
			Filter:      pc.Config.Update.GitHubMonitor.TagFilter,
			PackageName: pc.Hash,
		})
	}

	requestData := QueryReleaseData{
		RepoList: queries,
	}
	requestQuery := template(queryReleases, requestData)

	b, err := o.get(requestQuery)
	if err != nil {
		return nil, err
	}

	rs := QueryReleasesResponse{}
	err = json.Unmarshal(b, &rs)
	if err != nil {
		return nil, err
	}

	r, err := o.parseGitHubReleases(rs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse github releases: %w", err)
	}

	maps.Copy(results, r)

	return results, nil
}

func (o GitHubReleaseOptions) getGitHubTagVersions(repoList map[string]string) (results map[string]string, err error) {
	queries := []RepoQuery{}

	for packageName, ownerName := range repoList {
		pc, ok := o.PackageConfigs[packageName]
		if !ok {
			return nil, fmt.Errorf("no package config found for %s", packageName)
		}

		parts := strings.Split(ownerName, "/")
		if len(parts) != 2 {
			return nil, fmt.Errorf("malformed repo identifier should be in the form owner/repo, got %s", ownerName)
		}

		queries = append(queries, RepoQuery{
			Owner:       parts[0],
			Name:        parts[1],
			Filter:      pc.Config.Update.GitHubMonitor.TagFilter,
			PackageName: pc.Hash,
		})
	}

	requestData := QueryTagsData{
		RepoList: queries,
	}
	requestQuery := template(queryTags, requestData)

	b, err := o.get(requestQuery)
	if err != nil {
		return nil, err
	}

	rs := QueryTagsResponse{}
	err = json.Unmarshal(b, &rs)
	if err != nil {
		return nil, err
	}

	return o.parseGitHubTags(rs)
}

func (o GitHubReleaseOptions) get(requestQuery string) ([]byte, error) {
	// Define the JSON payload as a map[string]string
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

	// github graphql API returns 200 status + errors when cannot query repos
	if len(e.Errors) > 0 {
		return b, fmt.Errorf("error reponse from github %s", e.Errors[0].Message)
	}
	return b, nil
}

// using the response from the GitHub GraphQL API, parse it and return a slice of latest package versions
func (o GitHubReleaseOptions) parseGitHubTags(repos QueryTagsResponse) (results map[string]string, err error) {
	results = make(map[string]string)

	// for each repo queried, check for the latest version
	for packageNameHash, repo := range repos.Data {
		// strip prefix that avoids github thinking hash is not a float
		packageNameHash = strings.TrimPrefix(packageNameHash, "r")
		var versions []*version.Version
		c, ok := o.ConfigsByHash[packageNameHash]
		if !ok {
			return results, fmt.Errorf("no package config found for identifier %s", repo.NameWithOwner)
		}

		for _, node := range repo.Refs.Nodes {
			v, err := o.getVersion(packageNameHash, node.TagName, repo.NameWithOwner)
			if err != nil {
				o.ErrorMessages[c.Package.Name] = err.Error()
				continue
			}
			if v == nil {
				continue
			}
			versions = append(versions, v)
		}
		err = o.addIfNewVersion(packageNameHash, versions, repo.NameWithOwner, results)
		if err != nil {
			o.ErrorMessages[c.Package.Name] = err.Error()
		}
	}

	return results, nil
}

func (o GitHubReleaseOptions) parseGitHubReleases(repos QueryReleasesResponse) (results map[string]string, err error) {
	results = make(map[string]string)

	for packageNameHash, node := range repos.Data {
		// strip prefix that avoids github thinking hash is not a float
		packageNameHash = strings.TrimPrefix(packageNameHash, "r")
		var versions []*version.Version

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
			releaseVersion := release.Tag.Name
			if releaseVersion == "" {
				o.ErrorMessages[c.Package.Name] = fmt.Sprintf("no tag found for release %s", node.Name)
				continue
			}

			// if tag filter matched the prefix then skip
			if !strings.HasPrefix(releaseVersion, c.Update.GitHubMonitor.TagFilter) {
				continue
			}

			v, err := o.getVersion(packageNameHash, releaseVersion, node.NameWithOwner)
			if err != nil {
				o.ErrorMessages[c.Package.Name] = err.Error()
				continue
			}
			if v == nil {
				continue
			}
			versions = append(versions, v)
		}

		err = o.addIfNewVersion(packageNameHash, versions, node.NameWithOwner, results)
		if err != nil {
			o.ErrorMessages[c.Package.Name] = err.Error()
		}
	}

	return results, nil
}

func (o GitHubReleaseOptions) addIfNewVersion(packageNameHash string, versions []*version.Version, ownerName string, results map[string]string) error {
	// sort the versions to make sure we really do have the latest.
	// not all projects use the github latest release tag properly so could
	// end up with older versions
	if len(versions) > 0 {
		sort.Sort(wolfiversions.ByLatest(versions))

		latestVersionSemver := versions[len(versions)-1]

		// compare if this version is newer than the version we have in our
		// related melange package config
		c, ok := o.ConfigsByHash[packageNameHash]
		if !ok {
			return fmt.Errorf("failed to find %s in package configs", ownerName)
		}

		if c.Package.Version != "" {
			currentVersionSemver, err := version.NewVersion(c.Package.Version)
			if err != nil {
				return errors.Wrapf(err, "failed to create a version from package %s: %s", c.Package.Name, c.Package.Version)
			}

			if currentVersionSemver.Equal(latestVersionSemver) {
				o.Logger.Printf(
					"%s is on the latest version %s",
					c.Package.Name, latestVersionSemver.Original(),
				)
			}
			if currentVersionSemver.LessThan(latestVersionSemver) {
				o.Logger.Println(
					color.GreenString(
						fmt.Sprintf("there is a new stable version available %s, current wolfi version %s, new %s",
							c.Package.Name, c.Package.Version, latestVersionSemver.Original())))

				results[c.Package.Name] = latestVersionSemver.Original()
			}
		}
	}
	return nil
}

func (o GitHubReleaseOptions) shouldSkipVersion(v string) bool {
	invalid := []string{"alpha", "beta", "rc"}
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
		if c.Update.GitHubMonitor != nil {
			if c.Update.GitHubMonitor.UseTags {
				tagRepoQuery[c.Package.Name] = c.Update.GitHubMonitor.Identifier
			} else {
				releaseRepoQuery[c.Package.Name] = c.Update.GitHubMonitor.Identifier
			}
		}
	}

	return releaseRepoQuery, tagRepoQuery
}

func (o GitHubReleaseOptions) getVersion(nameHash, v, id string) (*version.Version, error) {
	// strip any prefix chars using mapper data
	// the fastest way to check is to lookup git repo name in the map
	// data, but there's no guarantee the repo name and map data key are
	// the same if the identifiers don't match fall back to iterating
	// through all map data to match using identifier
	c, ok := o.ConfigsByHash[nameHash]
	if !ok {
		return nil, fmt.Errorf("no melange package found for github response key / idendifier name %s", id)
	}
	ghm := c.Update.GitHubMonitor
	if ghm == nil {
		return nil, fmt.Errorf("no github update config found for package %s", id)
	}
	if ghm.StripPrefix != "" {
		v = strings.TrimPrefix(v, ghm.StripPrefix)
	}

	if c.Update.VersionSeparator != "" {
		v = strings.ReplaceAll(v, c.Update.VersionSeparator, ".")
	}

	if o.shouldSkipVersion(v) {
		return nil, nil
	}

	releaseVersionSemver, err := version.NewVersion(v)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create a version from %s: %s", id, v)
	}

	return releaseVersionSemver, nil
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
