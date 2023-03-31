package gh

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"

	http2 "github.com/wolfi-dev/wolfictl/pkg/http"
	"golang.org/x/time/rate"

	"golang.org/x/oauth2"

	"github.com/google/go-github/v50/github"
)

const SecondsToSleepWhenRateLimited = 30

type GitHubOperations interface {
	CheckExistingIssue(ctx context.Context, r *Issues) (string, error)
	OpenIssue(ctx context.Context, r *Issues) (string, error)
	OpenPullRequest(pr *NewPullRequest) (string, error)
	AddReactionIssue(ctx context.Context, i *Issues, number int, reaction string) error
	HasExistingComment(ctx context.Context, r *Issues, issueNumber int, newComment string) (bool, error)
	CommentIssue(ctx context.Context, r *Issues, number int) (string, error)
}

type BasePullRequest struct {
	Owner                 string
	RepoName              string
	Branch                string
	PullRequestBaseBranch string
	Retries               int
}

type GitOptions struct {
	GithubClient *github.Client
	MaxRetries   int
	Logger       *log.Logger
}

func New() GitOptions {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)

	ratelimit := &http2.RLHTTPClient{
		Client: oauth2.NewClient(context.Background(), ts),

		// 1 request every (n) second(s) to avoid DOS'ing server. https://docs.github.com/en/rest/guides/best-practices-for-integrators?apiVersion=2022-11-28#dealing-with-secondary-rate-limits
		Ratelimiter: rate.NewLimiter(rate.Every(3*time.Second), 1),
	}

	return GitOptions{
		GithubClient: github.NewClient(ratelimit.Client),
		Logger:       log.New(log.Writer(), "wolfictl gh release: ", log.LstdFlags|log.Lmsgprefix),
	}
}

/*
Code modified from original.  Credited to https://github.com/gruntwork-io/git-xargs/blob/f68178c5878108f32c63e1cb027eb1b5b93caaac/repository/repo-operations.go#L404
*/

func (o GitOptions) handleRateLimit(action func() (*github.Response, error)) error {
	resp, err := action()

	if resp.StatusCode == http.StatusUnauthorized {
		return errors.Wrap(err, "failed to auth with github, does your personal access token have the repo scope? https://github.com/settings/tokens/new?scopes=repo")
	}

	if err != nil {
		if githubErr := github.CheckResponse(resp.Response); githubErr != nil {
			isRateLimited, delay := o.checkRateLimiting(githubErr)
			if isRateLimited {
				o.Logger.Printf("retrying again later with %d second delay due to secondary rate limiting.", delay)
				time.Sleep(delay)
				return o.handleRateLimit(action)
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
