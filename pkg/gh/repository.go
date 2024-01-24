package gh

import (
	"context"

	"github.com/google/go-github/v58/github"
)

func (o GitOptions) ListRepositoryFiles(ctx context.Context, owner, repo, path, ref string) ([]*github.RepositoryContent, error) {
	opts := github.RepositoryContentGetOptions{
		Ref: ref,
	}

	_, directoryContents, _, err := o.GithubClient.Repositories.GetContents(ctx, owner, repo, path, &opts)
	if err != nil {
		return nil, err
	}
	return directoryContents, nil
}

func (o GitOptions) RepositoryFilesContents(ctx context.Context, owner, repo, file, ref string) (*github.RepositoryContent, error) {
	opts := github.RepositoryContentGetOptions{
		Ref: ref,
	}

	fileContent, _, _, err := o.GithubClient.Repositories.GetContents(ctx, owner, repo, file, &opts)
	if err != nil {
		return nil, err
	}

	return fileContent, nil
}
