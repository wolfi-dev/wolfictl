package git

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/pkg/errors"

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
	RawURL       string
}

func GetRemoteURLFromDir(dir string) (*URL, error) {
	r, err := git.PlainOpen(dir)
	if err != nil {
		return nil, err
	}
	return GetRemoteURL(r)
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
			gitURL.RawURL = fmt.Sprintf("https://%s/%s/%s.git", gitURL.Host, gitURL.Organisation, gitURL.Name)
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
	gitURL.RawURL = rawURL

	return gitURL, nil
}

func GetGitAuthorSignature() *object.Signature {
	gitAuthorName := os.Getenv("GIT_AUTHOR_NAME")
	gitAuthorEmail := os.Getenv("GIT_AUTHOR_EMAIL")
	// override default git config tagger info
	if gitAuthorName != "" && gitAuthorEmail != "" {
		return &object.Signature{
			Name:  gitAuthorName,
			Email: gitAuthorEmail,
			When:  time.Now(),
		}
	}
	return nil
}

func SetGitSignOptions(repoPath string) error {
	cmd := exec.Command("git", "config", "--local", "commit.gpgsign", "true")
	cmd.Dir = repoPath
	rs, err := cmd.Output()
	if err != nil {
		return errors.Wrapf(err, "failed to set git config gpgsign: %s", rs)
	}

	cmd = exec.Command("git", "config", "--local", "gpg.x509.program", "gitsign")
	cmd.Dir = repoPath
	rs, err = cmd.Output()
	if err != nil {
		return errors.Wrapf(err, "failed to set git config gpg.x509.program: %s", rs)
	}

	cmd = exec.Command("git", "config", "--local", "gpg.format", "x509")
	cmd.Dir = repoPath
	rs, err = cmd.Output()
	if err != nil {
		return errors.Wrapf(err, "failed to set git config gpg.format: %s", rs)
	}

	gitAuthorName := os.Getenv("GIT_AUTHOR_NAME")
	gitAuthorEmail := os.Getenv("GIT_AUTHOR_EMAIL")
	if gitAuthorName == "" || gitAuthorEmail == "" {
		return fmt.Errorf("missing GIT_AUTHOR_NAME and/or GIT_AUTHOR_EMAIL environment variable, please set")
	}

	cmd = exec.Command("git", "config", "--local", "user.name", gitAuthorName)
	cmd.Dir = repoPath
	rs, err = cmd.Output()
	if err != nil {
		return errors.Wrapf(err, "failed to set git config user.name: %s", rs)
	}

	cmd = exec.Command("git", "config", "--local", "user.email", gitAuthorEmail)
	cmd.Dir = repoPath
	rs, err = cmd.Output()
	if err != nil {
		return errors.Wrapf(err, "failed to set git config user.email: %s", rs)
	}

	return nil
}
