package git

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/go-git/go-git/v5/plumbing/transport"

	"github.com/go-git/go-git/v5"
	"github.com/wolfi-dev/wolfictl/pkg/stringhelpers"

	gitHttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

func GetGitAuth() *gitHttp.BasicAuth {
	gitToken := os.Getenv("GITHUB_TOKEN")

	if gitToken == "" {
		// If the token is empty, there's no way we can return a usable authentication
		// anyway. Whereas if we return nil, and don't auth, we have a chance at
		// succeeding with access of a public repo.
		return nil
	}

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
	if rawURL == "" {
		return nil, fmt.Errorf("no URL provided")
	}

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
		return fmt.Errorf("failed to set git config gpgsign %q: %w", rs, err)
	}

	cmd = exec.Command("git", "config", "--local", "gpg.x509.program", "gitsign")
	cmd.Dir = repoPath
	rs, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to set git config gpg.x509.program %q: %w", rs, err)
	}

	cmd = exec.Command("git", "config", "--local", "gpg.format", "x509")
	cmd.Dir = repoPath
	rs, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to set git config gpg.format %q: %w", rs, err)
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
		return fmt.Errorf("failed to set git config user.name %q: %w", rs, err)
	}

	cmd = exec.Command("git", "config", "--local", "user.email", gitAuthorEmail)
	cmd.Dir = repoPath
	rs, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to set git config user.email %q: %w", rs, err)
	}

	return nil
}

// TempClone clones the repo using the provided HTTPS URL to a temp directory,
// and returns the path to the temp directory.
//
// If hash is non-empty, the repo will be checked out to that commit hash.
//
// If user authentication is requested, a personal access token will be read in
// from the GITHUB_TOKEN environment variable.
//
// The caller is responsible for cleaning up the temp directory.
func TempClone(gitURL, hash string, useAuth bool) (repoDir string, err error) {
	dir, err := os.MkdirTemp("", "wolfictl-git-clone-*")
	if err != nil {
		return dir, fmt.Errorf("unable to create temp directory for git clone: %w", err)
	}

	var auth transport.AuthMethod
	if useAuth {
		auth = GetGitAuth()
	}

	repo, err := git.PlainClone(dir, false, &git.CloneOptions{
		Auth: auth,
		URL:  gitURL,
	})
	if err != nil {
		return dir, fmt.Errorf("unable to clone repo %q to temp directory: %w", gitURL, err)
	}

	if hash != "" {
		w, err := repo.Worktree()
		if err != nil {
			return "", fmt.Errorf("unable to get worktree for repo %q: %w", gitURL, err)
		}
		err = w.Checkout(&git.CheckoutOptions{
			Hash: plumbing.NewHash(hash),
		})
		if err != nil {
			return "", fmt.Errorf("unable to checkout hash %q for repo %q: %w", hash, gitURL, err)
		}
	}

	return dir, nil
}

// FindForkPoint finds the fork point between the local branch and the upstream
// branch.
//
// The fork point is the commit hash of the latest commit had in common between
// the local branch and the upstream branch.
//
// The local branch is the branch pointed to by the provided branchRef.
//
// The upstream branch is the branch pointed to by the provided upstreamRef.
//
// The caller is responsible for closing the provided repo.
func FindForkPoint(repo *git.Repository, branchRef, upstreamRef *plumbing.Reference) (*plumbing.Hash, error) {
	// Get the commit object for the local branch
	localCommit, err := repo.CommitObject(branchRef.Hash())
	if err != nil {
		return nil, err
	}

	// Get the commit iterator for the upstream branch
	upstreamIter, err := repo.Log(&git.LogOptions{From: upstreamRef.Hash()})
	if err != nil {
		return nil, err
	}
	defer upstreamIter.Close()

	// Collect all upstream commit hashes for comparison
	upstreamCommits := make(map[plumbing.Hash]bool)
	err = upstreamIter.ForEach(func(c *object.Commit) error {
		upstreamCommits[c.Hash] = true
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Now walk through the local branch commits to find where it diverged
	localIter, err := repo.Log(&git.LogOptions{From: localCommit.Hash})
	if err != nil {
		return nil, err
	}
	defer localIter.Close()

	var forkPoint *plumbing.Hash
	err = localIter.ForEach(func(c *object.Commit) error {
		if _, exists := upstreamCommits[c.Hash]; exists {
			// This commit exists in both histories, so it's a common ancestor and potential fork point
			forkPoint = &c.Hash
			// We stop iterating as we found the most recent common commit
			return storer.ErrStop
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if forkPoint == nil {
		return nil, fmt.Errorf("fork point not found")
	}

	return forkPoint, nil
}
