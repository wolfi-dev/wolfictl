package gh

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-github/v58/github"
)

type Issues struct {
	Owner       string
	RepoName    string
	PackageName string
	Comment     string
	Title       string
	Labels      []string
}

func (o GitOptions) ListIssues(ctx context.Context, owner, repo, state string) ([]*github.Issue, error) {
	var openIssues []*github.Issue

	err := o.handleRateLimitList(func(opt *github.ListOptions) (*github.Response, error) {
		ilo := github.IssueListByRepoOptions{
			State:       state,
			ListOptions: *opt,
		}
		issues, resp, err := o.GithubClient.Issues.ListByRepo(ctx, owner, repo, &ilo)
		openIssues = append(openIssues, issues...)
		return resp, err
	})

	return openIssues, err
}

func (o GitOptions) CheckExistingIssue(ctx context.Context, r *Issues) (int, error) {
	var openIssues []*github.Issue

	err := o.handleRateLimitList(func(opt *github.ListOptions) (*github.Response, error) {
		ilo := github.IssueListByRepoOptions{
			State:       "open",
			ListOptions: *opt,
		}
		issues, resp, err := o.GithubClient.Issues.ListByRepo(ctx, r.Owner, r.RepoName, &ilo)
		openIssues = append(openIssues, issues...)
		return resp, err
	})

	if err != nil {
		return 0, err
	}

	for _, issue := range openIssues {
		if strings.EqualFold(*issue.Title, r.Title) {
			return *issue.Number, nil
		}
	}
	return 0, nil
}

func (o GitOptions) HasExistingComment(ctx context.Context, r *Issues, issueNumber int, newComment string) (bool, error) {
	var comments []*github.IssueComment
	err := o.handleRateLimitList(func(opt *github.ListOptions) (*github.Response, error) {
		ilo := &github.IssueListCommentsOptions{
			ListOptions: *opt,
		}
		rs, resp, err := o.GithubClient.Issues.ListComments(ctx, r.Owner, r.RepoName, issueNumber, ilo)
		comments = append(comments, rs...)
		return resp, err
	})

	if err != nil {
		return false, err
	}

	for _, existingComment := range comments {
		if newComment == *existingComment.Body {
			return true, nil
		}
	}
	return false, nil
}

func (o GitOptions) OpenIssue(ctx context.Context, r *Issues) (string, error) {
	newIssue := &github.IssueRequest{
		Title:  github.String(r.Title),
		Body:   github.String(r.Comment),
		Labels: &r.Labels,
	}

	var issue *github.Issue
	err := o.handleRateLimit(func() (*github.Response, error) {
		createdIssue, resp, err := o.GithubClient.Issues.Create(ctx, r.Owner, r.RepoName, newIssue)
		issue = createdIssue
		return resp, err
	})

	if err != nil {
		return "", err
	}

	return issue.GetHTMLURL(), nil
}

func (o GitOptions) CloseIssue(background context.Context, organisation, name, comment string, i int) error {
	issue := &github.IssueRequest{
		State: github.String("closed"),
		Body:  github.String(comment),
	}
	_, _, err := o.GithubClient.Issues.Edit(background, organisation, name, i, issue)
	if err != nil {
		return fmt.Errorf("error closing issue %d: %s", i, err)
	}
	return nil
}

func (o GitOptions) CommentIssue(ctx context.Context, owner, repo, comment string, number int) (string, error) {
	ic := &github.IssueComment{
		Body: github.String(comment),
	}
	var issue *github.IssueComment
	err := o.handleRateLimit(func() (*github.Response, error) {
		updatedIssue, resp, err := o.GithubClient.Issues.CreateComment(ctx, owner, repo, number, ic)
		issue = updatedIssue
		return resp, err
	})

	return issue.GetHTMLURL(), err
}

func (o GitOptions) LabelIssue(ctx context.Context, owner, repo string, number int, labels *[]string) error {
	ir := &github.IssueRequest{
		Labels: labels,
	}
	err := o.handleRateLimit(func() (*github.Response, error) {
		_, resp, err := o.GithubClient.Issues.Edit(ctx, owner, repo, number, ir)
		return resp, err
	})
	return err
}

func (o GitOptions) AddReactionIssue(ctx context.Context, i *Issues, number int, reaction string) error {
	err := o.handleRateLimit(func() (*github.Response, error) {
		_, resp, err := o.GithubClient.Reactions.CreateIssueReaction(ctx, i.Owner, i.RepoName, number, reaction)
		return resp, err
	})
	return err
}

func GetErrorIssueTitle(bot, packageName string) string {
	return fmt.Sprintf("%s/%s", bot, packageName)
}
func GetUpdateIssueTitle(packageName, version string) string {
	return fmt.Sprintf("%s/%s new package update", packageName, version)
}
