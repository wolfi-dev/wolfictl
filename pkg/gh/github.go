package gh

import (
	"context"
	"fmt"
	"github.com/google/go-github/v48/github"
	"github.com/pkg/errors"
	"log"
	"time"
)

/*
Code modified from original.  Credited to https://github.com/gruntwork-io/git-xargs/blob/f68178c5878108f32c63e1cb027eb1b5b93caaac/repository/repo-operations.go#L404
*/

type PullRequest struct {
	Owner                 string
	RepoName              string
	Branch                string
	PullRequestBaseBranch string
	Title                 string
	Body                  string
	Retries               int
}

type GitOptions struct {
	GithubClient                  *github.Client
	MaxPullRequestRetries         int
	SecondsToSleepWhenRateLimited int
	Logger                        *log.Logger
}

// OpenPullRequest opens a pull request on GitHub
func (o GitOptions) OpenPullRequest(pr PullRequest) (string, error) {

	// If the current request has already exhausted the configured number of PR retries, short-circuit
	if pr.Retries > o.MaxPullRequestRetries {
		return "", fmt.Errorf("failed max number of retries, tried %d max %d", pr.Retries, o.MaxPullRequestRetries)
	}

	// Configure pull request options that the GitHub client accepts when making calls to open new pull requests
	newPR := &github.NewPullRequest{
		Title: github.String(pr.Title),
		Head:  github.String(pr.Branch),
		Base:  github.String(pr.PullRequestBaseBranch),
		Body:  github.String(pr.Body),
	}

	// make a pull request
	githubPR, resp, err := o.GithubClient.PullRequests.Create(context.Background(), pr.Owner, pr.RepoName, newPR)

	// The go-gh library's CheckResponse method can return two different types of rate limiting error:
	// 1. AbuseRateLimitError which may contain a Retry-After header whose value we can use to slow down, or
	// 2. RateLimitError which may contain information about when the rate limit will be removed, that we can also use to slow down
	// Therefore, we need to use type assertions to test for each type of error response, and accordingly fetch the data it may contain
	// about how long we should wait before its next attempt to open a pull request
	githubErr := github.CheckResponse(resp.Response)

	if githubErr != nil {

		var isRateLimited = false

		// If this request has been seen before, increment its retries count, taking into account previous iterations
		pr.Retries++

		var delay time.Duration
		// If GitHub returned an error of type RateLimitError, we can attempt to compute the next time to try the request again
		// by reading its rate limit information
		if rateLimitError, ok := githubErr.(*github.RateLimitError); ok {
			isRateLimited = true
			retryAfter := time.Until(rateLimitError.Rate.Reset.Time)
			delay = retryAfter
			o.Logger.Printf("parsed retryAfter %d from GitHub rate limit error's reset time", retryAfter)
		}

		// If GitHub returned a Retry-After header, use its value, otherwise use the default
		if abuseRateLimitError, ok := githubErr.(*github.AbuseRateLimitError); ok {
			isRateLimited = true
			if abuseRateLimitError.RetryAfter != nil {
				if abuseRateLimitError.RetryAfter.Seconds() > 0 {
					delay = *abuseRateLimitError.RetryAfter
				}
			}
		}

		if isRateLimited {

			// If we couldn't determine a more accurate delay from GitHub API response headers, then fall back to our user-configurable default
			if delay == 0 {
				delay = time.Duration(o.SecondsToSleepWhenRateLimited)
			}
			o.Logger.Printf("retrying PR for repo: %s again later with %d second delay due to secondary rate limiting.", pr.RepoName, delay)
			time.Sleep(delay * time.Second)

			// retry opening a pull request
			return o.OpenPullRequest(pr)
		}
	}

	if err != nil {
		return "", errors.Wrapf(err, "failed opening pull request")
	}

	return githubPR.GetHTMLURL(), nil
}
