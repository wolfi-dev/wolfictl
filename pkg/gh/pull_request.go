package gh

import (
	"context"
	"fmt"

	"github.com/google/go-github/v58/github"
)

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

// OpenPullRequest opens a pull request on GitHub
func (o GitOptions) OpenPullRequest(ctx context.Context, pr *NewPullRequest) (*github.PullRequest, error) {
	// Configure pull request options that the GitHub client accepts when making calls to open new pull requests
	newPR := &github.NewPullRequest{
		Title: github.String(pr.Title),
		Head:  github.String(pr.Branch),
		Base:  github.String(pr.PullRequestBaseBranch),
		Body:  github.String(pr.Body),
	}

	var githubPR *github.PullRequest
	err := o.handleRateLimit(func() (*github.Response, error) {
		createdPR, resp, err := o.GithubClient.PullRequests.Create(ctx, pr.Owner, pr.RepoName, newPR)
		githubPR = createdPR
		return resp, err
	})

	if err != nil {
		return nil, fmt.Errorf("failed opening pull request: %w", err)
	}

	return githubPR, nil
}

// ListPullRequests returns a list of pull requests for a given state using pagination
func (o GitOptions) ListPullRequests(ctx context.Context, owner, repo, state string) ([]*github.PullRequest, error) {
	openPullRequests := []*github.PullRequest{}

	err := o.handleRateLimitList(func(opt *github.ListOptions) (*github.Response, error) {
		opts := &github.PullRequestListOptions{
			State:       state,
			ListOptions: *opt,
		}
		prs, resp, err := o.GithubClient.PullRequests.List(ctx, owner, repo, opts)
		openPullRequests = append(openPullRequests, prs...)
		return resp, err
	})

	return openPullRequests, err
}

func (o GitOptions) ClosePullRequest(ctx context.Context, owner, repo string, number int) error {
	closed := "closed"
	pr := &github.PullRequest{
		State: &closed,
	}

	err := o.handleRateLimit(func() (*github.Response, error) {
		_, resp, err := o.GithubClient.PullRequests.Edit(ctx, owner, repo, number, pr)
		return resp, err
	})

	return err
}
