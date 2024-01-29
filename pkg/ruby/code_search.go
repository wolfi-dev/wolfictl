package ruby

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path"

	"github.com/google/go-github/v58/github"

	"github.com/wolfi-dev/wolfictl/pkg/gh"
)

// SearchResult represents Github Code Search results
type SearchResult struct {
	Repository string
	FilePath   string
	URL        string
	Fragments  []string
}

// CodeSearch is the main search function which uses Github Code Search to run
// the specified query for a particular package.
func (o *Options) CodeSearch(ctx context.Context, pkg *Package, query string) error {
	results, err := o.runQuery(ctx, pkg, query)
	if err != nil {
		return fmt.Errorf("searching code: %w", err)
	}

	md := generateMarkdown(results, query)
	fmt.Printf("%s", md)

	if len(results) > 0 {
		return fmt.Errorf("found %d potential matches", len(results))
	}
	return nil
}

// defaultSHA returns the latest SHA for the default branch of a given repo. It
// is used to calculate the corresponding cache file.
func (o *Options) defaultSHA(ctx context.Context, pkg *Package) (string, error) {
	client := github.NewClient(o.Client.Client)

	// Get the repository
	repository, _, err := client.Repositories.Get(ctx, pkg.Repo.Organisation, pkg.Repo.Name)
	if err != nil {
		return "", err
	}

	// Get the main branch reference
	reference, _, err := client.Git.GetRef(ctx, pkg.Repo.Organisation, pkg.Repo.Name, "heads/"+*repository.DefaultBranch)
	if err != nil {
		return "", err
	}

	// Get the commit SHA of the main branch
	return *reference.Object.SHA, nil
}

// cachedSearchResult returns the path for a cache file
func (o *Options) cachedSearchResult(pkg *Package, sha, query string) string {
	return path.Join(rubyCacheDirectory, pkg.Name, fmt.Sprintf("%s-%s.json", sha, url.QueryEscape(query)))
}

// runQuery performs a code search using the Github API given a particular
// query string. It will append a repo:xxx/yyy to only search one repo at a
// time for a particular query string.
//
// A note on caching:
//
// Github limits searches even further than normal API calls. To get around
// this (mainly to make dev easier) the raw json result is cached to make it
// easy to probe further without hitting the Github API every single time.
// Because Github Code Search limits searching to the default branch only, the
// cached file is named with the latest commit sha on the default branch. That
// way the cache does not get stale if new changes are made to the repository.
func (o *Options) runQuery(ctx context.Context, pkg *Package, query string) ([]SearchResult, error) {
	sha, err := o.defaultSHA(ctx, pkg)
	if err != nil {
		return nil, fmt.Errorf("getting default branch sha: %w", err)
	}

	cachedPath := o.cachedSearchResult(pkg, sha, query)
	_, err = os.Stat(cachedPath)
	if (err != nil && errors.Is(err, os.ErrNotExist)) || o.NoCache {
		// file does not exist OR we want to run the query without considering the cache
		err := o.runQueryAndCache(ctx, pkg, query, cachedPath)
		if err != nil {
			return nil, fmt.Errorf("running query: %w", err)
		}
	} else if err != nil {
		// error checking the file info
		return nil, fmt.Errorf("checking cache file: %w", err)
	}

	cached, err := os.Open(cachedPath)
	if err != nil {
		return nil, fmt.Errorf("opening cached file: %w", err)
	}
	defer cached.Close()

	rawResults, err := io.ReadAll(cached)
	if err != nil {
		return nil, err
	}

	var result github.CodeSearchResult
	err = json.Unmarshal(rawResults, &result)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling json: %w", err)
	}

	// Process the search results
	var results []SearchResult
	for _, codeResult := range result.CodeResults {
		result := SearchResult{
			Repository: codeResult.Repository.GetName(),
			FilePath:   *codeResult.Path,
			URL:        *codeResult.HTMLURL,
			Fragments:  []string{},
		}
		for _, fragment := range codeResult.TextMatches {
			result.Fragments = append(result.Fragments, fragment.GetFragment())
		}
		results = append(results, result)
	}

	return results, nil
}

// runQueryAndCache actually runs the Github code search. It will cache the
// result on disk for the next run.
func (o *Options) runQueryAndCache(ctx context.Context, pkg *Package, query, cachedPath string) error {
	logger := log.New(log.Writer(), "wolfictl ruby code-search: ", log.LstdFlags|log.Lmsgprefix)

	client := github.NewClient(o.Client.Client)
	gitOpts := gh.GitOptions{
		GithubClient: client,
		Logger:       logger,
	}

	query = fmt.Sprintf("%s repo:%s/%s", query, pkg.Repo.Organisation, pkg.Repo.Name)
	result, err := gitOpts.SearchCode(ctx, query)
	if err != nil {
		fmt.Printf("Error: %+v\n", err)
		return err
	}

	err = os.MkdirAll(path.Dir(cachedPath), 0o755)
	if err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	cached, err := os.Create(cachedPath)
	if err != nil {
		return fmt.Errorf("failed to create cache file: %w", err)
	}

	// Convert the struct to JSON
	jsonData, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshaling json: %w", err)
	}

	_, err = cached.Write(jsonData)
	if err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	defer cached.Close()
	return nil
}

func generateMarkdown(results []SearchResult, query string) string {
	message := fmt.Sprintf("query='%s'\n", query)
	if len(results) < 1 {
		message += "Search did not flag any results\n"
	}
	for _, result := range results {
		message += fmt.Sprintf("* %s\n", result.URL)
		for _, fragment := range result.Fragments {
			message += "```ruby\n"
			message += fmt.Sprintf("%s\n", fragment)
			message += "```\n"
		}
		message += "\n"
	}
	return message
}
