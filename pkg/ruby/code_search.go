package ruby

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path"

	"github.com/google/go-github/v55/github"

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
func (o *RubyOptions) CodeSearch(pkg *RubyPackage, query string) error {
	results, err := o.runQuery(pkg, query)
	if err != nil {
		return fmt.Errorf("Searching code: %w", err)
	}
	fmt.Printf("Found %d matches\n", len(results))
	for _, result := range results {
		fmt.Printf("%s\n", result.URL)
		for i, fragment := range result.Fragments {
			fmt.Printf(" %d. %s\n\n", i, fragment)
		}
	}
	return nil
}

// defaultSHA returns the latest SHA for the default branch of a given repo. It
// is used to calculate the corresponding cache file.
func (o *RubyOptions) defaultSHA(pkg *RubyPackage) (string, error) {
	ctx := context.Background()
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
func (o *RubyOptions) cachedSearchResult(pkg *RubyPackage, sha, query string) (string, error) {
	return path.Join(rubyCacheDirectory, pkg.Name, fmt.Sprintf("%s-%s.json", sha, url.QueryEscape(query))), nil
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
func (o *RubyOptions) runQuery(pkg *RubyPackage, query string) ([]SearchResult, error) {
	logger := log.New(log.Writer(), "wolfictl ruby code-search: ", log.LstdFlags|log.Lmsgprefix)
	sha, err := o.defaultSHA(pkg)
	if err != nil {
		return nil, fmt.Errorf("Getting default branch sha: %w", err)
	}

	cachedPath, err := o.cachedSearchResult(pkg, sha, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get gemspec cache path")
	}

	cached, err := os.Open(cachedPath)
	if err != nil || o.NoCache {
		ctx := context.Background()

		client := github.NewClient(o.Client.Client)
		query = fmt.Sprintf("%s repo:%s/%s", query, pkg.Repo.Organisation, pkg.Repo.Name)
		gitOpts := gh.GitOptions{
			GithubClient: client,
			Logger:       logger,
		}

		result, err := gitOpts.SearchCode(ctx, query)
		if err != nil {
			fmt.Printf("Error: %+v\n", err)
			return nil, err
		}

		err = os.MkdirAll(path.Dir(cachedPath), 0o755)
		if err != nil {
			return nil, fmt.Errorf("failed to create cache directory: %w", err)
		}

		cached, err = os.Create(cachedPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create cache file: %w", err)
		}

		// Convert the struct to JSON
		jsonData, err := json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("marshaling json: %w", err)
		}

		_, err = cached.Write(jsonData)
		if err != nil {
			return nil, fmt.Errorf("failed to write cache file: %w", err)
		}
		cached.Seek(0, io.SeekStart)

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

func generateMessage(results []SearchResult) (string, error) {
	if len(results) < 1 {
		return "Search did not flag any results", nil
	}
	return "", nil
}
