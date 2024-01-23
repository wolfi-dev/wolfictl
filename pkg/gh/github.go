package gh

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/go-github/v58/github"
)

const SecondsToSleepWhenRateLimited = 30

type GitHubOperations interface {
	CheckExistingIssue(ctx context.Context, r *Issues) (string, error)
	OpenIssue(ctx context.Context, r *Issues) (string, error)
	OpenPullRequest(ctx context.Context, pr *NewPullRequest) (string, error)
	AddReactionIssue(ctx context.Context, i *Issues, number int, reaction string) error
	HasExistingComment(ctx context.Context, r *Issues, issueNumber int, newComment string) (bool, error)
	CommentIssue(ctx context.Context, r *Issues, number int) (string, error)
	ListIssues(ctx context.Context, owner, repo, state string) ([]*github.Issue, error)
	ListPullRequests(ctx context.Context, owner, repo, state string) ([]*github.PullRequest, error)
}

type BasePullRequest struct {
	Owner                 string
	RepoName              string
	Branch                string
	PullRequestBaseBranch string
}

type GitOptions struct {
	GithubClient *github.Client
	MaxRetries   int
	Logger       *log.Logger
}

/*
Code modified from original.  Credited to https://github.com/gruntwork-io/git-xargs/blob/f68178c5878108f32c63e1cb027eb1b5b93caaac/repository/repo-operations.go#L404
*/

func (o GitOptions) handleRateLimit(action func() (*github.Response, error)) error {
	resp, err := action()
	return o.handleGitHubResponse(resp, err, func() error {
		return o.handleRateLimit(action)
	})
}

func (o GitOptions) handleRateLimitList(action func(opt *github.ListOptions) (*github.Response, error)) error {
	opt := &github.ListOptions{
		PerPage: 30,
	}

	for {
		resp, err := action(opt)

		err = o.handleGitHubResponse(resp, err, func() error {
			return o.handleRateLimitList(action)
		})
		if err != nil {
			return err
		}

		if resp.NextPage == 0 {
			break
		}

		opt.Page = resp.NextPage
	}
	return nil
}

func (o GitOptions) handleGitHubResponse(resp *github.Response, err error, action func() error) error {
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("failed to auth with GitHub, does your personal access token have the repo scope? https://github.com/settings/tokens/new?scopes=repo. status code: %d", resp.StatusCode)
	}
	if err != nil {
		if githubErr := github.CheckResponse(resp.Response); githubErr != nil {
			isRateLimited, delay := o.checkRateLimiting(githubErr)
			if isRateLimited {
				o.Logger.Printf("retrying again later with %v second delay due to secondary rate limiting.", delay.Seconds())
				time.Sleep(delay)
				return action()
			}
			return githubErr
		}
		return err
	}
	return nil
}

func (o GitOptions) checkRateLimiting(githubErr error) (bool, time.Duration) {
	isRateLimited := false

	delay := time.Duration(SecondsToSleepWhenRateLimited * int(time.Second))
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
	return isRateLimited, delay
}
