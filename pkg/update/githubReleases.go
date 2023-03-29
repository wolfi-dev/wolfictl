package update

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	gotemplate "text/template"

	"github.com/fatih/color"

	"chainguard.dev/melange/pkg/build"

	"github.com/pkg/errors"

	"github.com/hashicorp/go-version"
	http2 "github.com/wolfi-dev/wolfictl/pkg/http"

	"github.com/shurcooL/githubv4"
	"github.com/wolfi-dev/wolfictl/pkg/melange"
	wolfiversions "github.com/wolfi-dev/wolfictl/pkg/versions"
	"golang.org/x/exp/maps"
)

const (
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

func NewGitHubReleaseOptions(configs map[string]melange.Packages, gqlClient *githubv4.Client, ghClient *http2.RLHTTPClient) GitHubReleaseOptions {
	options := GitHubReleaseOptions{
		GitGraphQLClient: gqlClient,
		Logger:           log.New(log.Writer(), "wolfictl update: ", log.LstdFlags|log.Lmsgprefix),
		PackageConfigs:   configs,
		GitHubHTTPClient: ghClient,
	}

	return options
}

type GitHubReleaseOptions struct {
	GitGraphQLClient *githubv4.Client
	GitHubHTTPClient *http2.RLHTTPClient
	Logger           *log.Logger
	PackageConfigs   map[string]melange.Packages
}

func (o GitHubReleaseOptions) getLatestGitHubVersions(errorMessages map[string]string) (results map[string]string, err error) {
	if len(o.PackageConfigs) == 0 {
		return results, errors.New("no melange configs found")
	}

	releaseRepoList, tagRepolist := o.getRepoLists()

	results, err = o.getGitHubReleaseVersions(releaseRepoList, errorMessages)
	if err != nil {
		return results, err
	}

	r, err := o.getGitHubTagVersions(tagRepolist, errorMessages)
	if err != nil {
		return results, err
	}

	// combine both release and tag versions from retrieved from GitHub
	maps.Copy(results, r)

	return results, err
}

func (o GitHubReleaseOptions) getGitHubReleaseVersions(releaseRepoList []map[string]string, errorMessages map[string]string) (results map[string]string, err error) {
	results = make(map[string]string)
	var q struct {
		Search `graphql:"search(first: $count, query: $searchQuery, type: REPOSITORY)"`
	}
	for _, batch := range releaseRepoList {
		var query []string
		for _, identifier := range batch {
			query = append(query, identifier)
		}
		variables := map[string]interface{}{
			"searchQuery": githubv4.String(strings.Join(query, " ")),
			"count":       githubv4.Int(100), // github states max 100 repos per request
			"first":       githubv4.Int(numberOfReleasesToReturn),
		}

		err := o.GitGraphQLClient.Query(context.Background(), &q, variables)
		if err != nil {
			return nil, err
		}

		repos := make([]Repository, len(q.Search.Nodes))

		for i, v := range q.Search.Nodes {
			repos[i] = v.Repository
		}

		r, err := o.parseGitHubReleases(repos, errorMessages)
		if err != nil {
			printJSON(q)
			return nil, fmt.Errorf("failed to parse github releases: %w", err)
		}

		maps.Copy(results, r)
	}
	return results, nil
}

func (o GitHubReleaseOptions) getGitHubTagVersions(repoList []map[string]string, errorMessages map[string]string) (results map[string]string, err error) {
	var queries []RepoQuery

	// batches are only needed for request releases from GitHub, no point in looping over all map entries again though so reusing the list structure
	for _, batches := range repoList {
		for _, repo := range batches {
			c, err := o.getMelangeConfig(repo)
			if err != nil {
				return nil, err
			}
			parts := strings.Split(repo, "/")

			if len(parts) != 2 {
				return nil, fmt.Errorf("malformed repo identifier should be in the form owner/repo, got %s", repo)
			}
			queries = append(queries, RepoQuery{
				Owner:  parts[0],
				Name:   parts[1],
				Filter: c.Update.GitHubMonitor.TagFilter,
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

	rs := QueryTagsResponse{}
	err = json.Unmarshal(b, &rs)
	if err != nil {
		return nil, err
	}

	return o.parseGitHubTags(rs, errorMessages)
}

// using the response from the GitHub GraphQL API, parse it and return a slice of latest package versions
func (o GitHubReleaseOptions) parseGitHubTags(repos QueryTagsResponse, errorMessages map[string]string) (results map[string]string, err error) {
	results = make(map[string]string)

	// for each repo queried, check for the latest version
	for _, repo := range repos.Data {
		var versions []*version.Version
		melangeConfig, err := o.getMelangeConfig(repo.NameWithOwner)
		if err != nil {
			return results, fmt.Errorf("no package config found for identifier %s", repo.NameWithOwner)
		}

		for _, node := range repo.Refs.Nodes {
			v, err := o.getVersion(node.TagName, repo.NameWithOwner)
			if err != nil {
				errorMessages[melangeConfig.Package.Name] = err.Error()
				continue
			}
			if v == nil {
				continue
			}
			versions = append(versions, v)
		}
		err = o.addIfNewVersion(versions, repo.NameWithOwner, results)
		if err != nil {
			errorMessages[melangeConfig.Package.Name] = err.Error()
		}
	}
	return results, nil
}

func (o GitHubReleaseOptions) parseGitHubReleases(repos []Repository, errorMessages map[string]string) (results map[string]string, err error) {
	results = make(map[string]string)

	for _, node := range repos {
		releases := node.Releases
		var versions []*version.Version

		// compare if this version is newer than the version we have in our
		// related melange package config
		melangePackageConfig, err := o.getMelangeConfig(string(node.NameWithOwner))
		if err != nil {
			return results, fmt.Errorf("failed to find %s in package configs", string(node.NameWithOwner))
		}

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
				errorMessages[melangePackageConfig.Package.Name] = fmt.Sprintf("no tag found for release %s", node.Name)
				continue
			}

			// if tag filter matched the prefix then skip
			if !strings.HasPrefix(releaseVersion, melangePackageConfig.Update.GitHubMonitor.TagFilter) {
				continue
			}

			v, err := o.getVersion(releaseVersion, string(node.NameWithOwner))
			if err != nil {
				errorMessages[melangePackageConfig.Package.Name] = err.Error()
				continue
			}
			if v == nil {
				continue
			}
			versions = append(versions, v)
		}

		err = o.addIfNewVersion(versions, string(node.NameWithOwner), results)
		if err != nil {
			errorMessages[melangePackageConfig.Package.Name] = err.Error()
		}
	}
	return results, nil
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
		melangePackageConfig, err := o.getMelangeConfig(ownerName)
		if err != nil {
			return fmt.Errorf("failed to find %s in package configs", ownerName)
		}

		if melangePackageConfig.Package.Version != "" {
			currentVersionSemver, err := version.NewVersion(melangePackageConfig.Package.Version)
			if err != nil {
				return errors.Wrapf(err, "failed to create a version from package %s: %s", melangePackageConfig.Package.Name, melangePackageConfig.Package.Version)
			}

			if currentVersionSemver.Equal(latestVersionSemver) {
				o.Logger.Printf(
					"%s is on the latest version %s",
					melangePackageConfig.Package.Name, latestVersionSemver.Original(),
				)
			}
			if currentVersionSemver.LessThan(latestVersionSemver) {
				o.Logger.Println(
					color.GreenString(
						fmt.Sprintf("there is a new stable version available %s, current wolfi version %s, new %s",
							melangePackageConfig.Package.Name, melangePackageConfig.Package.Version, latestVersionSemver.Original())))

				results[melangePackageConfig.Package.Name] = latestVersionSemver.Original()
			}
		}
	}
	return nil
}

func (o GitHubReleaseOptions) isVersionPreRelease(v *version.Version, id string) bool {
	invalid := []string{"alpha", "beta", "rc"}
	for _, i := range invalid {
		if strings.Contains(v.Prerelease(), i) {
			return true
		}
		// todo JR add back
		//if strings.Contains(strings.ToLower(v.Prerelease()), i) {
		//	return true
		//}
	}
	return false
}

// function returns batches of git repositories used to query githubs graphql api.  GitHub has a limit of 100 repos per request.
func (o GitHubReleaseOptions) getRepoLists() (releaseBatch, tagBatch []map[string]string) {
	releaseRepoQuery := make(map[string]string)
	tagRepoQuery := make(map[string]string)

	for i := range o.PackageConfigs {
		c := o.PackageConfigs[i].Config
		if c.Update.GitHubMonitor != nil {
			if c.Update.GitHubMonitor.UseTags {
				tagRepoQuery[c.Package.Name] = c.Update.GitHubMonitor.Identifier
			} else {
				releaseRepoQuery[c.Package.Name] = fmt.Sprintf("repo:%s", c.Update.GitHubMonitor.Identifier)
			}
		}
	}

	releaseBatch = getBatches(releaseRepoQuery)
	tagBatch = getBatches(tagRepoQuery)
	return releaseBatch, tagBatch
}

func (o GitHubReleaseOptions) getVersion(v, id string) (*version.Version, error) {
	// strip any prefix chars using mapper data
	// the fastest way to check is to lookup git repo name in the map
	// data, but there's no guarantee the repo name and map data key are
	// the same if the identifiers don't match fall back to iterating
	// through all map data to match using identifier
	p, err := o.getMelangeConfig(id)
	if p.Update.GitHubMonitor == nil {
		return nil, fmt.Errorf("no github update config found for package %s", id)
	}
	if p.Update.GitHubMonitor.StripPrefix != "" {
		v = strings.TrimPrefix(v, p.Update.GitHubMonitor.StripPrefix)
	}

	if p.Update.VersionSeparator != "" {
		v = strings.ReplaceAll(v, p.Update.VersionSeparator, ".")
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

// loop through slice of package configs and find teh matching identifier
// originally we turned the slice into a map key'd by identifier however,
// this caused an issue if we have more that one package that has update
// config for the same repo and hence same backend identifier.  Not able
// add the package name to the key as we don't know the package name when
// parsing graphql responses
func (o GitHubReleaseOptions) getMelangeConfig(identifier string) (build.Configuration, error) {
	for i := range o.PackageConfigs {
		ghm := o.PackageConfigs[i].Config.Update.GitHubMonitor
		if ghm == nil {
			continue
		}
		if ghm.Identifier == identifier {
			return o.PackageConfigs[i].Config, nil
		}
	}
	return build.Configuration{}, fmt.Errorf("no package config found with update identifier %s", identifier)
}

//	func getBatches(repoQuery map[string]string) []map[string]string {
//		numberOfRepos := len(repoQuery)
//
//		// divide the number of repos by 100 and round up to the next whole number
//		numberOfBatches := int(math.Ceil(float64(numberOfRepos) / 100))
//
//		batches := make([]map[string]string, numberOfBatches)
//
//		counter := 0
//		for i := 0; i < numberOfBatches; i++ {
//			// looping through the maps to declare
//			// batches of length 100
//
//			if i == numberOfBatches-1 {
//				// if this is the last batch, only make the map the size of remaining repos
//				batches[i] = make(map[string]string, len(repoQuery)-counter)
//			} else {
//				// create batches of 100
//				batches[i] = make(map[string]string, 100)
//			}
//
//			// fill up each batch with a map of repos
//			for j := 0; j < 100 && counter < len(repoQuery); j++ {
//				repoQuery
//				batches[i][j] = repoQuery[counter]
//				counter++
//			}
//		}
//
//		return batches
//	}
func getBatches(repoQuery map[string]string) []map[string]string {
	var sliceOfMaps []map[string]string
	if len(repoQuery) == 0 {
		return sliceOfMaps
	}
	sliceOfMaps = append(sliceOfMaps, make(map[string]string))

	count := 0
	// loop over all entries to add to slice
	for key, value := range repoQuery {
		// check if current map has reached max entries
		if count == 100 {
			// create new map and append to slice
			sliceOfMaps = append(sliceOfMaps, make(map[string]string))
			count = 0
		}
		// add entry to current map
		sliceOfMaps[len(sliceOfMaps)-1][key] = value
		count++
	}
	return sliceOfMaps
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

func template(tmpl string, data QueryTagsData) string {
	var buf bytes.Buffer
	t := gotemplate.Must(gotemplate.New("").Parse(tmpl))
	t.Option("missingkey=error")
	if err := t.Execute(&buf, data); err != nil {
		log.Fatalf("Executing template: %v", err)
	}
	return buf.String()
}
