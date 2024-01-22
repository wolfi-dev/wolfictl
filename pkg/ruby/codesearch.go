package ruby

import (
	"context"
	"fmt"
	"log"

	"github.com/google/go-github/v55/github"

	"github.com/wolfi-dev/wolfictl/pkg/gh"
	wgit "github.com/wolfi-dev/wolfictl/pkg/git"
)

// SearchResult represents a single code search result
type SearchResult struct {
	Repository string
	FilePath   string
	URL        string
}

func (rc *RubyRepoContext) CodeSearch(query string) error {
	results, err := rc.searchCode(query)
	if err != nil {
		return fmt.Errorf("Searching code: %w", err)
	}
	fmt.Printf("Found %d matches\n", len(results))
	for _, result := range results {
		fmt.Printf("%+v\n", result)
	}
	return nil
}

// searchCode performs a code search using the GitHub API
func (rc *RubyRepoContext) searchCode(query string) ([]SearchResult, error) {
	logger := log.New(log.Writer(), "wolfictl ruby: ", log.LstdFlags|log.Lmsgprefix)
	ctx := context.Background()

	client := github.NewClient(rc.Client.Client)
	gitURL, err := wgit.ParseGitURL(rc.Pkg.Repo)
	if err != nil {
		return []SearchResult{}, err
	}

	query = fmt.Sprintf("%s repo:%s/%s", query, gitURL.Organisation, gitURL.Name)
	fmt.Printf("Searching with: %s\n", query)
	gitOpts := gh.GitOptions{
		GithubClient: client,
		Logger:       logger,
	}
	result, err := gitOpts.SearchCode(ctx, query)
	if err != nil {
		fmt.Printf("Error: %+v\n", err)
		return nil, err
	}
	fmt.Printf("Searched\n")

	// Process the search results
	var results []SearchResult
	for _, codeResult := range result.CodeResults {
		result := SearchResult{
			Repository: codeResult.Repository.GetName(),
			FilePath:   *codeResult.Path,
			URL:        *codeResult.HTMLURL,
		}
		results = append(results, result)
	}

	return results, nil
}
