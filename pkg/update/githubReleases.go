package update

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"sort"
	"strings"

	"chainguard.dev/melange/pkg/build"

	"golang.org/x/exp/maps"

	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	"github.com/shurcooL/githubv4"
)

const (
	githubReleases = "GITHUB"
	// some git repos do not use the "latest" github release well
	// i.e. they perform a maintenance release of an old version but it can be marked as latest,
	// 1.2.3.4 gets released but marked as latest while 1.3.0 exists which is the version we want to check against
	// so we need to check previous number of versions to ensure we can locate the real latest release version
	numberOfReleasesToReturn = 10
)

type Search struct {
	RepositoryCount githubv4.Int
	Edges           []struct {
		Node struct {
			Repository struct {
				Releases struct {
					TotalCount  githubv4.Int
					ReleaseEdge []struct {
						Release struct {
							Name         githubv4.String
							IsPrerelease githubv4.Boolean
							IsDraft      githubv4.Boolean
							IsLatest     githubv4.Boolean
						} `graphql:"node"`
					} `graphql:"edges"`
				} `graphql:"releases(first: $first)"`
				Name          githubv4.String
				NameWithOwner githubv4.String
			} `graphql:"... on Repository"`
		}
	} `json:"Edges"`
}

func NewGitHubReleaseOptions(mapperData map[string]Row, configs map[string]build.Configuration, client *githubv4.Client) GitHubReleaseOptions {
	options := GitHubReleaseOptions{
		MapperData:       mapperData,
		GitGraphQLClient: client,
		Logger:           log.New(log.Writer(), "wolfictl update: ", log.LstdFlags|log.Lmsgprefix),
		StripPrefix:      make(map[string]string),
		PackageConfigs:   configs,
	}

	// maintain a different map, key'd by mapper data identifier for easy lookup
	for _, row := range mapperData {
		options.StripPrefix[row.Identifier] = row.StripPrefixChar
	}
	return options
}

type GitHubReleaseOptions struct {
	GitGraphQLClient *githubv4.Client
	Logger           *log.Logger
	MapperData       map[string]Row
	StripPrefix      map[string]string
	PackageConfigs   map[string]build.Configuration
}

func (o GitHubReleaseOptions) getLatestGitHubVersions() (map[string]string, []string, error) {
	results := make(map[string]string)
	var errorMessages []string

	if len(o.MapperData) == 0 {
		return results, errorMessages, nil
	}

	repoList := o.getRepoList(o.MapperData)
	var q struct {
		Search `graphql:"search(first: $count, query: $searchQuery, type: REPOSITORY)"`
	}
	for _, batch := range repoList {
		variables := map[string]interface{}{
			"searchQuery": githubv4.String(strings.Join(batch[:], " ")),
			"count":       githubv4.Int(100), // github say max 100 repos per request
			"first":       githubv4.Int(numberOfReleasesToReturn),
		}

		err := o.GitGraphQLClient.Query(context.Background(), &q, variables)
		if err != nil {
			return nil, nil, err
		}
		// printJSON(q)

		r, e, err := o.parseGitHubReleases(q.Search)
		if err != nil {
			printJSON(q)
			return nil, nil, errors.Wrap(err, "failed to parse github releases")
		}

		maps.Copy(results, r)

		errorMessages = append(errorMessages, e...)
	}

	return results, errorMessages, nil
}

func (o GitHubReleaseOptions) parseGitHubReleases(search Search) (map[string]string, []string, error) {
	results := make(map[string]string)
	var errorMessages []string
	for _, edge := range search.Edges {
		releases := edge.Node.Repository.Releases
		var versions []*version.Version

		// keep a map of original versions retrieved from github with a semver as the key so we can easily look it up after sorting
		originalVersions := make(map[*version.Version]string)
		for _, release := range releases.ReleaseEdge {
			if release.Release.IsDraft {
				continue
			}
			if release.Release.IsPrerelease {
				continue
			}
			releaseVersion := string(release.Release.Name)

			// strip any prefix chars using mapper data
			// the fastest way to check is to lookup git repo name in the map data, but there's no guarantee the repo name and map data key are the same
			// if the identifiers don't match fall back to iterating through all map data to match using identifier

			stripPrefix := o.StripPrefix[string(edge.Node.Repository.NameWithOwner)]
			if stripPrefix != "" {
				releaseVersion = strings.TrimPrefix(releaseVersion, stripPrefix)
			}

			releaseVersionSemver, err := version.NewVersion(releaseVersion)
			if err != nil {
				errorMessages = append(errorMessages, fmt.Sprintf("failed to create a version from package %s: %s.  Error: %s", edge.Node.Repository.NameWithOwner, releaseVersion, err))
				continue
			}

			versions = append(versions, releaseVersionSemver)

			originalVersions[releaseVersionSemver] = releaseVersion
		}

		// sort the versions to make sure we really do have the latest.
		// not all projects use the github latest release tag properly so could end up with older versions
		if len(versions) > 0 {
			sort.Sort(VersionsByLatest(versions))

			latestVersionSemver := versions[len(versions)-1]
			latestVersion := originalVersions[latestVersionSemver]

			// compare if this version is newer than the version we have in our related melange package config
			packageName := string(edge.Node.Repository.Name)
			melangePackageConfig := o.PackageConfigs[packageName]
			if melangePackageConfig.Package.Version != "" {

				currentVersionSemver, err := version.NewVersion(melangePackageConfig.Package.Version)
				if err != nil {
					errorMessages = append(errorMessages, fmt.Sprintf("failed to create a version from package %s: %s.  Error: %s", melangePackageConfig.Package.Name, melangePackageConfig.Package.Version, err))

					continue
				}

				if currentVersionSemver.LessThan(latestVersionSemver) {
					o.Logger.Printf("there is a new stable version available %s, current wolfi version %s, new %s", packageName, melangePackageConfig.Package.Version, latestVersion)
					results[string(edge.Node.Repository.Name)] = latestVersion
				}

			}

		}

	}
	return results, errorMessages, nil
}

// function returns batches of git repositories used to query githubs graphql api.  GitHub has a limit of 100 repos per request.
func (o GitHubReleaseOptions) getRepoList(mapperData map[string]Row) [][]string {
	var repoQuery []string

	for _, row := range mapperData {
		if row.ServiceName == githubReleases {
			repoQuery = append(repoQuery, fmt.Sprintf("repo:%s", row.Identifier))
		}
	}

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

type Interface interface {
	// Len is the number of elements in the collection.
	Len() int

	// Less reports whether the element with index i must sort before the element with index j.
	// If both Less(i, j) and Less(j, i) are false, then the elements at index i and j are considered equal.
	Less(i, j int) bool

	// Swap swaps the elements with indexes i and j.
	Swap(i, j int)
}

func (u VersionsByLatest) Len() int {
	return len(u)
}

func (u VersionsByLatest) Swap(i, j int) {
	u[i], u[j] = u[j], u[i]
}

func (u VersionsByLatest) Less(i, j int) bool {
	return u[i].LessThan(u[j])
}

type VersionsByLatest []*version.Version
