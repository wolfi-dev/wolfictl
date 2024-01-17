package ruby

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/google/go-github/v55/github"

	"github.com/wolfi-dev/wolfictl/pkg/gh"
	wgit "github.com/wolfi-dev/wolfictl/pkg/git"
)

func (rc *RubyRepoContext) Gemspec() (string, error) {
    // find the Gemspec
    gemspec, err := rc.findGemspec()
    if err != nil {
        return "", fmt.Errorf("finding gemspec: %w", err)
    }

    // download the Gemspec
    err = rc.fetchFile(gemspec)
    if err != nil {
        return "", fmt.Errorf("downloading gemspec: %w", err)
    }

    // search the gemspec for version constraints
    // TODO
    return "", nil
}

func (rc *RubyRepoContext) findGemspec() (string, error) {
	ctx := context.Background()
	client := github.NewClient(rc.Client.Client)
	gitOpts := gh.GitOptions{
		GithubClient: client,
	}

	gitURL, err := wgit.ParseGitURL(rc.Pkg.Repo)
	if err != nil {
		return "", err
	}

	directoryContents, err := gitOpts.ListRepositoryFiles(ctx, gitURL.Organisation, gitURL.Name, "", rc.Pkg.Ref)
	if err != nil {
		return "", err
	}

	for _, file := range directoryContents {
		fmt.Printf("  %s\n", file.GetName())
		if strings.HasSuffix(file.GetName(), gemspecSuffix) {
			return file.GetName(), nil
		}
	}
	return "", fmt.Errorf("Could not find gemspec")
}

func (rc *RubyRepoContext) fetchFile(file string) error {
	ctx := context.Background()

	gitURL, err := wgit.ParseGitURL(rc.Pkg.Repo)
	if err != nil {
		return err
	}

	client := github.NewClient(rc.Client.Client)
	gitOpts := gh.GitOptions{
		GithubClient: client,
	}
	fileContent, err := gitOpts.RepositoryFilesContents(ctx, gitURL.Organisation, gitURL.Name, file, rc.Pkg.Ref)
	if err != nil {
		return err
	}

	// Decode the base64-encoded content
	decodedContent, err := base64.StdEncoding.DecodeString(*fileContent.Content)
	if err != nil {
		return fmt.Errorf("Error decoding file content: %w", err)
	}

	fmt.Println("File downloaded successfully.")
	fmt.Printf("%s\n", string(decodedContent))
	return nil
}
