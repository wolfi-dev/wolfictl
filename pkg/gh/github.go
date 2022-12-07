package gh

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/go-version"

	"github.com/google/go-github/v48/github"
	"github.com/pkg/errors"
)

/*
Code modified from original.  Credited to https://github.com/gruntwork-io/git-xargs/blob/f68178c5878108f32c63e1cb027eb1b5b93caaac/repository/repo-operations.go#L404
*/

type BasePullRequest struct {
	Owner                 string
	RepoName              string
	Branch                string
	PullRequestBaseBranch string
	Retries               int
}
type NewPullRequest struct {
	BasePullRequest
	Title string
	Body  string
}

type GetPullRequest struct {
	BasePullRequest
	PackageName string
	Version     string
}

type GitOptions struct {
	GithubClient                  *github.Client
	MaxPullRequestRetries         int
	SecondsToSleepWhenRateLimited int
	Logger                        *log.Logger
}

// OpenPullRequest opens a pull request on GitHub
func (o GitOptions) OpenPullRequest(pr NewPullRequest) (string, error) {

	// if our new version is more recent that the existing PR close it and create a new one, otherwise skip

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

		isRateLimited, delay := o.checkRateLimiting(githubErr)

		if isRateLimited {

			// If this request has been seen before, increment its retries count, taking into account previous iterations
			pr.Retries++

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

func (o GitOptions) checkRateLimiting(githubErr error) (bool, time.Duration) {
	var isRateLimited = false

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
	return isRateLimited, delay
}

// CheckExistingPullRequests if an existing PR is open with the same version skip, if it's an older version close the PR and we'll create a new one
func (o GitOptions) CheckExistingPullRequests(pr GetPullRequest) (string, error) {
	// check if there's an existing PR open for the same package
	openPullRequests, resp, err := o.GithubClient.PullRequests.List(context.Background(), pr.Owner, pr.RepoName, &github.PullRequestListOptions{State: "open"})

	githubErr := github.CheckResponse(resp.Response)

	if githubErr != nil {

		isRateLimited, delay := o.checkRateLimiting(githubErr)

		if isRateLimited {

			// If this request has been seen before, increment its retries count, taking into account previous iterations
			pr.Retries++

			// If we couldn't determine a more accurate delay from GitHub API response headers, then fall back to our user-configurable default
			if delay == 0 {
				delay = time.Duration(o.SecondsToSleepWhenRateLimited)
			}
			o.Logger.Printf("retrying PR for repo: %s again later with %d second delay due to secondary rate limiting.", pr.RepoName, delay)
			time.Sleep(delay * time.Second)

			// retry opening a pull request
			return o.CheckExistingPullRequests(pr)
		}
	}

	for _, openPr := range openPullRequests {
		// if we already have a PR for the same version return
		if strings.HasPrefix(*openPr.Title, fmt.Sprintf("%s/%s", pr.PackageName, pr.Version)) {
			return openPr.GetHTMLURL(), nil
		}
		prTitle := *openPr.Title

		// if we have a PR for the package but a newer version return
		if strings.HasPrefix(prTitle, fmt.Sprintf("%s/", pr.PackageName)) {
			parts := strings.SplitAfter(prTitle, fmt.Sprintf("%s/", pr.PackageName))
			if len(parts) > 1 {
				continue
			}
			versionParts := strings.SplitAfter(parts[0], " ")
			if len(versionParts) == 0 {
				continue
			}

			currentVersionSemver, err := version.NewVersion(versionParts[0])
			if err != nil {
				continue
			}

			latestVersionSemver, err := version.NewVersion(pr.Version)
			if err != nil {
				o.Logger.Printf("failed to create a version from %s.  Error: %s", pr.Version, err)
				continue
			}

			if currentVersionSemver.LessThan(latestVersionSemver) {
				o.Logger.Printf("closing old pull request %s as we have a newer version %s", openPr.GetHTMLURL(), pr.Version)
				return "", o.closePullRequest(pr, openPr)
			}
		}
	}

	if err != nil {
		return "", errors.Wrapf(err, "failed listing pull requests")
	}
	return "", nil
}

func (o GitOptions) closePullRequest(pr GetPullRequest, openPr *github.PullRequest) error {
	closed := "closed"
	openPr.State = &closed
	_, resp, err := o.GithubClient.PullRequests.Edit(context.Background(), pr.Owner, pr.RepoName, *openPr.Number, openPr)
	githubErr := github.CheckResponse(resp.Response)

	if githubErr != nil {

		isRateLimited, delay := o.checkRateLimiting(githubErr)

		if isRateLimited {

			// If this request has been seen before, increment its retries count, taking into account previous iterations
			pr.Retries++

			// If we couldn't determine a more accurate delay from GitHub API response headers, then fall back to our user-configurable default
			if delay == 0 {
				delay = time.Duration(o.SecondsToSleepWhenRateLimited)
			}
			o.Logger.Printf("retrying PR for repo: %s again later with %d second delay due to secondary rate limiting.", pr.RepoName, delay)
			time.Sleep(delay * time.Second)

			// retry opening a pull request
			return o.closePullRequest(pr, openPr)
		}
	}
	return err
}
