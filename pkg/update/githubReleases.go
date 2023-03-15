package update

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	gotemplate "text/template"

	"github.com/pkg/errors"

	"github.com/hashicorp/go-version"
	http2 "github.com/wolfi-dev/wolfictl/pkg/http"

	"github.com/shurcooL/githubv4"
	"github.com/wolfi-dev/wolfictl/pkg/melange"
	wolfiversions "github.com/wolfi-dev/wolfictl/pkg/versions"
	"golang.org/x/exp/maps"
)

const (
	githubReleases = "GITHUB"
	// some git repos do not use the "latest" github release well
	// i.e. they perform a maintenance release of an old version but it can be marked as latest,
	// 1.2.3.4 gets released but marked as latest while 1.3.0 exists which is the version we want to check against
	// so we need to check previous number of versions to ensure we can locate the real latest release version
	numberOfReleasesToReturn = 10
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
  repo_{{$index}}: repository(owner: "{{$r.Owner}}", name: "{{$r.Name}}") {
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

/*

The graphql query used is the equivalent contained in this comment, which can be tested using GitHub's graphql explorer
https://docs.github.com/en/graphql/overview/explorer

__NOTE__ if using the explorer to generate responses to extend unit tests, you will need to strip off

search
{
  "data": {
    "search": {
      "repositoryCount": #,
      "nodes":

		...

       }
    }
}

Query https://docs.github.com/en/graphql/overview/explorer

{
  search(type: REPOSITORY, query: "repo:jenkinsci/jenkins repo:sigstore/cosign", first: 100) {
    repositoryCount
    nodes {

      ... on Repository  {
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
      }
    }
  }
}
*/

type Search struct {
	RepositoryCount githubv4.Int `graphql:"repositoryCount"`
	Nodes           []struct {
		Repository Repository `graphql:"... on Repository"`
	}
}

type Repository struct {
	Owner struct {
		Login githubv4.String `graphql:"login"`
	} `json:"Owner"`
	Name          githubv4.String `graphql:"name"`
	NameWithOwner githubv4.String `graphql:"nameWithOwner"`
	Releases      struct {
		TotalCount githubv4.Int `graphql:"totalCount"`
		Nodes      []struct {
			Tag struct {
				Name githubv4.String `graphql:"name"`
			} `json:"Tag"`
			Name         githubv4.String  `graphql:"name"`
			IsPrerelease githubv4.Boolean `graphql:"isPrerelease"`
			IsDraft      githubv4.Boolean `graphql:"isDraft"`
			IsLatest     githubv4.Boolean `graphql:"isLatest"`
		} `graphql:"nodes"`
	} `graphql:"releases(first: $first)"`
}

func NewGitHubReleaseOptions(mapperData map[string]Row, configs map[string]melange.Packages, gqlClient *githubv4.Client, ghClient *http2.RLHTTPClient) GitHubReleaseOptions {
	options := GitHubReleaseOptions{
		MapperData:             mapperData,
		GitGraphQLClient:       gqlClient,
		Logger:                 log.New(log.Writer(), "wolfictl update: ", log.LstdFlags|log.Lmsgprefix),
		MapperDataByIdentifier: make(map[string]Row),
		PackageConfigs:         configs,
		GitHubHTTPClient:       ghClient,
	}

	// maintain a different map, key'd by mapper data identifier for easy lookup
	for _, row := range mapperData {
		if row.ServiceName == "GITHUB" {
			options.MapperDataByIdentifier[row.Identifier] = row
		}
	}
	return options
}

type GitHubReleaseOptions struct {
	GitGraphQLClient       *githubv4.Client
	GitHubHTTPClient       *http2.RLHTTPClient
	Logger                 *log.Logger
	MapperData             map[string]Row
	MapperDataByIdentifier map[string]Row
	PackageConfigs         map[string]melange.Packages
}

func (o GitHubReleaseOptions) getLatestGitHubVersions() (map[string]string, []string, error) {
	var results map[string]string
	var errorMessages []string

	if len(o.MapperData) == 0 {
		o.Logger.Println("no mapping data, skip checking github versions")
		return results, errorMessages, nil
	}

	releaseRepoList, tagRepolist := o.getRepoLists(o.MapperData)

	results, errorMessages, err := o.getGitHubReleaseVersions(releaseRepoList)
	if err != nil {
		return results, errorMessages, errors.Wrapf(err, "failed to get github release  versions")
	}

	r, e, err := o.getGitHubTagVersions(tagRepolist)
	if err != nil {
		return results, errorMessages, errors.Wrapf(err, "failed to get github tag versions")
	}

	// append any error messages from getting tag versions to the release version error messages
	errorMessages = append(errorMessages, e...)

	// combine both release and tag versions from retrieved from GitHub
	maps.Copy(results, r)

	return results, errorMessages, nil
}

func (o GitHubReleaseOptions) getGitHubReleaseVersions(releaseRepoList [][]string) (map[string]string, []string, error) {
	results := make(map[string]string)
	var errorMessages []string
	var q struct {
		Search `graphql:"search(first: $count, query: $searchQuery, type: REPOSITORY)"`
	}
	for _, batch := range releaseRepoList {
		variables := map[string]interface{}{
			"searchQuery": githubv4.String(strings.Join(batch, " ")),
			"count":       githubv4.Int(100), // github states max 100 repos per request
			"first":       githubv4.Int(numberOfReleasesToReturn),
		}

		err := o.GitGraphQLClient.Query(context.Background(), &q, variables)
		if err != nil {
			return nil, nil, err
		}

		repos := make([]Repository, len(q.Search.Nodes))

		for i, v := range q.Search.Nodes {
			repos[i] = v.Repository
		}

		r, e, err := o.parseGitHubReleases(repos)
		if err != nil {
			printJSON(q)
			return nil, nil, fmt.Errorf("failed to parse github releases: %w", err)
		}

		// todo why?
		maps.Copy(results, r)

		errorMessages = append(errorMessages, e...)
	}
	return results, errorMessages, nil
}

func (o GitHubReleaseOptions) getGitHubTagVersions(repoList [][]string) (map[string]string, []string, error) {

	var queries []RepoQuery

	// batches are only needed for request releases from GitHub, no point in looping over all map entries again though so reusing the list structure
	for _, batches := range repoList {
		for _, repo := range batches {
			filter := o.MapperDataByIdentifier[repo].TagFilter
			parts := strings.Split(repo, "/")

			if len(parts) != 2 {
				return nil, nil, fmt.Errorf("malformed repo identifier should be in the form owner/repo, got %s", repo)
			}
			queries = append(queries, RepoQuery{
				Owner:  parts[0],
				Name:   parts[1],
				Filter: filter,
			})
		}
	}
	requestData := QueryTagsData{
		RepoList: queries,
	}
	requestQuery := template(queryTags, requestData)

	// Define the JSON payload as a map[string]string
	payload := map[string]string{
		"query": requestQuery,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	o.Logger.Printf("request: %s", requestQuery)

	req, err := http.NewRequest("POST", "https://api.github.com/graphql", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, nil, err
	}

	token := os.Getenv("GITHUB_TOKEN")
	req.Header.Add("Authorization", fmt.Sprintf("bearer %s", token))
	resp, err := o.GitHubHTTPClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("non ok http response for github graphql code: %v %s", resp.StatusCode, resp.Status)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	rs := QueryTagsResponse{}
	err = json.Unmarshal(b, &rs)
	if err != nil {
		return nil, nil, err
	}

	return o.parseGitHubTags(rs)
}

func (o GitHubReleaseOptions) parseGitHubTags(repos QueryTagsResponse) (results map[string]string, errorMessages []string, err error) {

	results = make(map[string]string)

	for _, repo := range repos.Data {
		var versions []*version.Version
		for _, node := range repo.Refs.Nodes {
			v, err := o.getVersion(node.TagName, repo.NameWithOwner)
			if err != nil {
				errorMessages = append(errorMessages, err.Error())
				continue
			}
			if v == nil {
				continue
			}
			versions = append(versions, v)
		}
		err = o.addIfNewVersion(versions, repo.NameWithOwner, results)
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
		}
	}
	return results, errorMessages, nil
}

func (o GitHubReleaseOptions) parseGitHubReleases(repos []Repository) (results map[string]string, errorMessages []string, err error) {

	results = make(map[string]string)

	for _, node := range repos {
		releases := node.Releases
		var versions []*version.Version

		// keep a map of original versions retrieved from github with a semver as the key so we can easily look it up after sorting
		for _, release := range releases.Nodes {
			if release.IsDraft {
				continue
			}
			if release.IsPrerelease {
				continue
			}

			// first get the version from the release name but fall back to using the tag
			releaseVersion := string(release.Tag.Name)
			if releaseVersion == "" {
				errorMessages = append(errorMessages, fmt.Sprintf(
					"no tag found for release %s",
					node.Name,
				))
				continue
			}

			v, err := o.getVersion(releaseVersion, string(node.NameWithOwner))
			if err != nil {
				errorMessages = append(errorMessages, err.Error())
				continue
			}
			if v == nil {
				continue
			}
			versions = append(versions, v)
		}

		err = o.addIfNewVersion(versions, string(node.NameWithOwner), results)
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
		}
	}
	return results, errorMessages, nil
}

func (o GitHubReleaseOptions) addIfNewVersion(versions []*version.Version, ownerName string, results map[string]string) error {

	// sort the versions to make sure we really do have the latest.
	// not all projects use the github latest release tag properly so could
	// end up with older versions
	if len(versions) > 0 {
		sort.Sort(wolfiversions.ByLatest(versions))

		latestVersionSemver := versions[len(versions)-1]

		// compare if this version is newer than the version we have in our
		// related melange package config
		melangePackageName := o.MapperDataByIdentifier[ownerName].PackageName
		melangePackageConfig, ok := o.PackageConfigs[melangePackageName]
		if !ok {
			return fmt.Errorf("failed to find %s in package configs", melangePackageName)
		}

		if melangePackageConfig.Config.Package.Version != "" {
			currentVersionSemver, err := version.NewVersion(melangePackageConfig.Config.Package.Version)
			if err != nil {
				return errors.Wrapf(err, "failed to create a version from package %s: %s", melangePackageConfig.Config.Package.Name, melangePackageConfig.Config.Package.Version)
			}

			if currentVersionSemver.LessThan(latestVersionSemver) {
				o.Logger.Printf(
					"there is a new stable version available %s, current wolfi version %s, new %s",
					ownerName, melangePackageConfig.Config.Package.Version, latestVersionSemver.Original(),
				)
				results[melangePackageName] = latestVersionSemver.Original()
			}
		}
	}
	return nil
}

func (o GitHubReleaseOptions) isVersionPreRelease(v *version.Version, id string) bool {
	invalid := []string{"alpha", "beta", "rc"}
	for _, i := range invalid {
		if strings.Contains(v.Prerelease(), i) {
			o.Logger.Printf("auto updates cannot be used for pre-releases,  %s with %s versions", id, v.Prerelease())
			return true
		}
	}
	return false
}

// function returns batches of git repositories used to query githubs graphql api.  GitHub has a limit of 100 repos per request.
func (o GitHubReleaseOptions) getRepoLists(mapperData map[string]Row) ([][]string, [][]string) {
	var releaseRepoQuery []string
	var tagRepoQuery []string

	for _, row := range mapperData {
		if row.ServiceName == githubReleases {
			if row.UseTags {
				tagRepoQuery = append(tagRepoQuery, row.Identifier)
			} else {
				releaseRepoQuery = append(releaseRepoQuery, fmt.Sprintf("repo:%s", row.Identifier))
			}
		}
	}

	releaseBatch := getBatches(releaseRepoQuery)
	tagBatch := getBatches(tagRepoQuery)
	return releaseBatch, tagBatch
}

func (o GitHubReleaseOptions) getVersion(v, id string) (*version.Version, error) {
	// strip any prefix chars using mapper data
	// the fastest way to check is to lookup git repo name in the map
	// data, but there's no guarantee the repo name and map data key are
	// the same if the identifiers don't match fall back to iterating
	// through all map data to match using identifier
	p := o.MapperDataByIdentifier[id]
	if p.StripPrefixChar != "" {
		v = strings.TrimPrefix(v, p.StripPrefixChar)
	}

	if p.StripSuffixChar != "" {
		v = strings.TrimPrefix(v, p.StripSuffixChar)
	}

	releaseVersionSemver, err := version.NewVersion(v)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create a version from %s: %s", id, v)

	}

	if o.isVersionPreRelease(releaseVersionSemver, id) {
		return nil, nil
	}
	return releaseVersionSemver, nil
}

func getBatches(repoQuery []string) [][]string {
	numberOfRepos := len(repoQuery)

	// divide the number of repos by 100 and round up to the next whole number
	numberOfBatches := int(math.Ceil(float64(numberOfRepos) / 100))

	batches := make([][]string, numberOfBatches)

	counter := 0
	for i := 0; i < numberOfBatches; i++ {
		// looping through the slice to declare
		// batches of length 100

		if i == numberOfBatches-1 {
			// if this is the last batch, only make the slice the size of remaining repos
			batches[i] = make([]string, len(repoQuery)-counter)
		} else {
			// create batches of 100
			batches[i] = make([]string, 100)
		}

		// fill up each batch with a slice of repos
		for j := 0; j < 100 && counter < len(repoQuery); j++ {
			batches[i][j] = repoQuery[counter]
			counter++
		}
	}

	return batches
}

// printJSON prints v as JSON encoded with indent to stdout. It panics on any error.
func printJSON(v interface{}) {
	w := json.NewEncoder(os.Stdout)
	w.SetIndent("", "\t")
	err := w.Encode(v)
	if err != nil {
		panic(err)
	}
}

type QueryTagsData struct {
	RepoList []RepoQuery
}
type RepoQuery struct {
	Owner  string
	Name   string
	Filter string
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

type QueryTagsResponse struct {
	Data map[string]Repo `json:"data"`
}

func template(tmpl string, data QueryTagsData) string {
	var buf bytes.Buffer
	t := gotemplate.Must(gotemplate.New("").Parse(tmpl))
	t.Option("missingkey=error")
	if err := t.Execute(&buf, data); err != nil {
		log.Fatalf("Executing template: %v", err)
	}
	return buf.String()
}
