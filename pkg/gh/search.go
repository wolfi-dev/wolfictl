package gh

import (
	"context"
	"fmt"
	"time"

	"github.com/google/go-github/v58/github"
)

// SearchCode does a rate-limited search using the Github Code Search API. It
// does not currently do paginated search, that would be a good feature to add,
// but is not needed for it's immediate use case.
func (o GitOptions) SearchCode(ctx context.Context, query string) (*github.CodeSearchResult, error) {
	options := &github.SearchOptions{
		TextMatch: true,
	}
	var result *github.CodeSearchResult

	for {
		rs, resp, err := o.GithubClient.Search.Code(ctx, query, options)

		// if no err return result
		if err == nil {
			result = rs
			break
		}

		// if err is rate limit, delay and try again
		githubErr := github.CheckResponse(resp.Response)
		if githubErr != nil {
			rateLimited, delay := o.checkRateLimiting(githubErr)
			if !rateLimited {
				return nil, githubErr
			}
			fmt.Printf("retrying after %v second delay due to rate limiting\n", delay.Seconds())
			time.Sleep(delay)
		} else {
			// if err is not rate limit, return err
			return nil, err
		}
	}
	return result, nil
}
