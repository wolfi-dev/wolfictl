package gh

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-github/v50/github"
)

type Issues struct {
	Owner       string
	RepoName    string
	PackageName string
	Comment     string
	Retries     int
	Title       string
}

func (o GitOptions) CheckExistingIssue(ctx context.Context, r *Issues) (int, error) {
	var openIssues []*github.Issue

	ilo := github.IssueListByRepoOptions{State: "open"}
	err := o.handleRateLimit(func() (*github.Response, error) {
		issues, resp, err := o.GithubClient.Issues.ListByRepo(ctx, r.Owner, r.RepoName, &ilo)
		openIssues = issues
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

	opt := &github.IssueListCommentsOptions{}
	err := o.handleRateLimit(func() (*github.Response, error) {
		rs, resp, err := o.GithubClient.Issues.ListComments(ctx, r.Owner, r.RepoName, issueNumber, opt)
		comments = rs
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
	if r.Retries > o.MaxRetries {
		return "", fmt.Errorf("failed max number of retries, tried %d max %d", r.Retries, o.MaxRetries)
	}

	newIssue := &github.IssueRequest{
		Title: github.String(r.Title),
		Body:  github.String(r.Comment),
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

func (o GitOptions) CommentIssue(ctx context.Context, r *Issues, number int) (string, error) {
	ic := &github.IssueComment{
		Body: &r.Comment,
	}
	var issue *github.IssueComment
	err := o.handleRateLimit(func() (*github.Response, error) {
		updatedIssue, resp, err := o.GithubClient.Issues.CreateComment(ctx, r.Owner, r.RepoName, number, ic)
		issue = updatedIssue
		return resp, err
	})

	return issue.GetHTMLURL(), err
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
