package update

import (
	"context"
	"fmt"
	"log"
	"sort"

	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	"github.com/shurcooL/githubv4"
)

const (
	githubReleases = "GITHUB"
)

// Query details about a GitHub repository releases
var releasesQuery struct {
	Search `graphql:"search(first: $count, query: $searchQuery, type: REPOSITORY)"`
}

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
				NameWithOwner githubv4.String
			} `graphql:"... on Repository"`
		}
	} `json:"Edges"`
}

type GitHubReleaseOptions struct {
	GitGraphQLClient *githubv4.Client
	Logger           *log.Logger
	DataMapperURL    string
}

func (o GitHubReleaseOptions) getLatestGitHubVersions(mapperData map[string]Row) (map[string]string, []string, error) {
	packagesToUpdate := make(map[string]string)
	var repoQuery []string

	for _, row := range mapperData {
		if row.ServiceName == githubReleases {
			repoQuery = append(repoQuery, fmt.Sprintf("repo: %s ", row.Identifier))
		}
	}

	// graphql api has a limit of 100 repos per request, lets split this out
	variables := map[string]interface{}{
		"searchQuery": githubv4.String(fmt.Sprintf("%s", repoQuery)),
		"count":       githubv4.Int(100),
		"first":       githubv4.Int(20),
	}

	err := o.GitGraphQLClient.Query(context.Background(), &releasesQuery, variables)
	if err != nil {
		if err != nil {
			return packagesToUpdate, []string{}, errors.Wrapf(err, "failed to query github graphql, query %v with variables %s", releasesQuery, variables)
		}
	}

	return o.parseGitHubReleases(releasesQuery.Search)

}

func (m GitHubReleaseOptions) parseGitHubReleases(search Search) (map[string]string, []string, error) {
	results := make(map[string]string)
	var errorMessages []string
	for _, edge := range search.Edges {
		releases := edge.Node.Repository.Releases
		var versions []*version.Version

		// keep a map of original versions retrived from github with a semver as the key so we can easily look it up after sorting
		originalVersions := make(map[*version.Version]string)
		for _, release := range releases.ReleaseEdge {
			if release.Release.IsDraft {
				continue
			}
			if release.Release.IsPrerelease {
				continue
			}
			releaseVersion := string(release.Release.Name)
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
			latestVersion := originalVersions[versions[len(versions)-1]]
			results[string(edge.Node.Repository.NameWithOwner)] = latestVersion
		}

	}
	return results, errorMessages, nil
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
