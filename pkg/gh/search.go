package gh

import (
	"context"
	"fmt"
	"time"

	"github.com/google/go-github/v55/github"
)

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
			if rateLimited {
				fmt.Printf("retrying after %v second delay due to rate limiting", delay.Seconds())
				time.Sleep(delay)
			} else {
				return nil, githubErr
			}
		} else {
			// if err is not rate limit, return err
			return nil, err
		}
	}
	return result, nil
}
