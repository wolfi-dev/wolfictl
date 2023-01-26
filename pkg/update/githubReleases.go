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

	"github.com/hashicorp/go-version"

	"github.com/shurcooL/githubv4"
	"github.com/wolfi-dev/wolfictl/pkg/melange"
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

__NOTE__ if using the explorer to generate responses to extend unit tests, you will need to strip off

searxh
{
  "data": {
    "search": {
      "repositoryCount": #,
      "nodes": [


Query https://docs.github.com/en/graphql/overview/explorer

{
  search(type: REPOSITORY, query: "repo:jenkinsci/jenkins repo:sigstore/cosign", first: 100) {
    repositoryCount
    nodes

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

func NewGitHubReleaseOptions(mapperData map[string]Row, configs map[string]melange.Packages, client *githubv4.Client) GitHubReleaseOptions {
	options := GitHubReleaseOptions{
		MapperData:       mapperData,
		GitGraphQLClient: client,
		Logger:           log.New(log.Writer(), "wolfictl update: ", log.LstdFlags|log.Lmsgprefix),
		PackageConfigIDs: make(map[string]string),
		PackageConfigs:   configs,
	}

	// maintain a different map, key'd by mapper data identifier for easy lookup
	for _, row := range mapperData {
		options.PackageConfigIDs[row.Identifier] = row.StripPrefixChar
	}
	return options
}

type GitHubReleaseOptions struct {
	GitGraphQLClient *githubv4.Client
	Logger           *log.Logger
	MapperData       map[string]Row
	PackageConfigIDs map[string]string
	PackageConfigs   map[string]melange.Packages
}

func (o GitHubReleaseOptions) getLatestGitHubVersions() (results map[string]string, errorMessages []string, err error) {
	results = make(map[string]string)

	if len(o.MapperData) == 0 {
		return results, errorMessages, nil
	}

	repoList := o.getRepoList(o.MapperData)
	var q struct {
		Search `graphql:"search(first: $count, query: $searchQuery, type: REPOSITORY)"`
	}
	for _, batch := range repoList {
		variables := map[string]interface{}{
			"searchQuery": githubv4.String(strings.Join(batch, " ")),
			"count":       githubv4.Int(100), // github say max 100 repos per request
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

		maps.Copy(results, r)

		errorMessages = append(errorMessages, e...)
	}

	return results, errorMessages, nil
}

//nolint:unparam // Is this waiting for better error handling?
func (o GitHubReleaseOptions) parseGitHubReleases(repos []Repository) (results map[string]string, errorMessages []string, err error) {
	results = make(map[string]string)
	for _, node := range repos {
		releases := node.Releases
		var versions []*version.Version

		// keep a map of original versions retrieved from github with a semver as the key so we can easily look it up after sorting
		originalVersions := make(map[*version.Version]string)
		for _, release := range releases.Nodes {
			if release.IsDraft {
				continue
			}
			if release.IsPrerelease {
				continue
			}

			// first get teh version from the release name but fall back to using the tag
			releaseVersion := string(release.Name)
			if releaseVersion == "" {
				o.Logger.Printf("GitHub %s no release name found, falling back to release tag", node.Name)
				releaseVersion = string(release.Tag.Name)
				if releaseVersion == "" {
					errorMessages = append(errorMessages, fmt.Sprintf(
						"no release name or tag found for release %s",
						node.Name,
					))
					continue
				}
			}

			// strip any prefix chars using mapper data
			// the fastest way to check is to lookup git repo name in the map
			// data, but there's no guarantee the repo name and map data key are
			// the same if the identifiers don't match fall back to iterating
			// through all map data to match using identifier

			stripPrefix := o.PackageConfigIDs[string(node.NameWithOwner)]
			if stripPrefix != "" {
				releaseVersion = strings.TrimPrefix(releaseVersion, stripPrefix)
			}

			releaseVersionSemver, err := version.NewVersion(releaseVersion)
			if err != nil {
				errorMessages = append(errorMessages, fmt.Sprintf(
					"failed to create a version from package %s: %s.  Error: %s",
					node.NameWithOwner, releaseVersion, err,
				))
				continue
			}

			versions = append(versions, releaseVersionSemver)

			originalVersions[releaseVersionSemver] = releaseVersion
		}

		// sort the versions to make sure we really do have the latest.
		// not all projects use the github latest release tag properly so could
		// end up with older versions
		if len(versions) > 0 {
			sort.Sort(VersionsByLatest(versions))

			latestVersionSemver := versions[len(versions)-1]
			latestVersion := originalVersions[latestVersionSemver]

			// compare if this version is newer than the version we have in our
			// related melange package config
			packageName := string(node.Name)
			melangePackageConfig, ok := o.PackageConfigs[packageName]
			if !ok {
				errorMessages = append(errorMessages, fmt.Sprintf(
					"failed to find %s in package configs",
					packageName,
				))
				continue
			}
			if melangePackageConfig.Config.Package.Version != "" {
				currentVersionSemver, err := version.NewVersion(melangePackageConfig.Config.Package.Version)
				if err != nil {
					errorMessages = append(errorMessages, fmt.Sprintf(
						"failed to create a version from package %s: %s.  Error: %s",
						melangePackageConfig.Config.Package.Name, melangePackageConfig.Config.Package.Version, err,
					))
					continue
				}
				o.Logger.Printf("is %s less than %s", currentVersionSemver.String(), latestVersionSemver.String())
				if currentVersionSemver.LessThan(latestVersionSemver) {
					o.Logger.Printf(
						"there is a new stable version available %s, current wolfi version %s, new %s",
						packageName, melangePackageConfig.Config.Package.Version, latestVersion,
					)
					results[string(node.Name)] = latestVersion
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
