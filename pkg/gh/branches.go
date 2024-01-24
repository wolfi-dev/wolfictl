package gh

import (
	"context"

	"github.com/google/go-github/v58/github"
)

func (o GitOptions) ListBranches(ctx context.Context, owner, repo string) ([]*github.Branch, error) {
	var branches []*github.Branch

	err := o.handleRateLimitList(func(opt *github.ListOptions) (*github.Response, error) {
		ilo := github.BranchListOptions{
			ListOptions: *opt,
		}
		rs, resp, err := o.GithubClient.Repositories.ListBranches(ctx, owner, repo, &ilo)
		branches = append(branches, rs...)
		return resp, err
	})

	return branches, err
}
