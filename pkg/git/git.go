package git

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/wolfi-dev/wolfictl/pkg/stringhelpers"

	gitHttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

func GetGitAuth() *gitHttp.BasicAuth {
	gitToken := os.Getenv("GITHUB_TOKEN")

	return &gitHttp.BasicAuth{
		Username: "abc123",
		Password: gitToken,
	}
}

type URL struct {
	Scheme       string
	Host         string
	Organisation string
	Name         string
}

func GetRemoteURL(repo *git.Repository) (*URL, error) {
	remote, err := repo.Remote("origin")
	if err != nil {
		return nil, fmt.Errorf("failed to find git origin URL: %w", err)
	}

	if len(remote.Config().URLs) == 0 {
		return nil, fmt.Errorf("no remote config URLs found for remote origin")
	}

	return ParseGitURL(remote.Config().URLs[0])
}

// ParseGitURL returns owner, repo name, errors
func ParseGitURL(rawURL string) (*URL, error) {
	gitURL := &URL{}

	rawURL = strings.TrimSuffix(rawURL, ".git")

	// handle git@ kinds of URIs
	if strings.HasPrefix(rawURL, "git@") {
		t := strings.TrimPrefix(rawURL, "git@")
		t = strings.TrimPrefix(t, "/")
		t = strings.TrimPrefix(t, "/")
		t = strings.TrimSuffix(t, "/")

		arr := stringhelpers.RegexpSplit(t, ":|/")
		if len(arr) >= 3 {
			gitURL.Scheme = "git"
			gitURL.Host = arr[0]
			gitURL.Organisation = arr[1]
			gitURL.Name = arr[len(arr)-1]
			return gitURL, nil
		}
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return gitURL, fmt.Errorf("failed to parse git url %s: %w", rawURL, err)
	}
	gitURL.Scheme = parsedURL.Scheme
	gitURL.Host = parsedURL.Host
	parts := strings.Split(parsedURL.Path, "/")
	gitURL.Organisation = parts[1]
	gitURL.Name = parts[2]

	return gitURL, nil
}
