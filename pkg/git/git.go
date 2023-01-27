package git

import (
	"os"

	gitHttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

func GetGitAuth() *gitHttp.BasicAuth {
	gitToken := os.Getenv("GITHUB_TOKEN")

	return &gitHttp.BasicAuth{
		Username: "abc123",
		Password: gitToken,
	}
}
