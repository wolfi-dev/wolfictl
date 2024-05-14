package advisory

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/go-github/v58/github"
	"github.com/google/uuid"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
	wgit "github.com/wolfi-dev/wolfictl/pkg/git"
)

type DataSession struct {
	tempDir          string
	repo             *git.Repository
	workingBranch    string
	distro           distro.Distro
	index            *configs.Index[v2.Document]
	githubClient     *github.Client
	modified         bool
	modifiedPackages []string
}

type DataSessionOptions struct {
	Distro       distro.Distro
	GitHubClient *github.Client
}

// NewDataSession initializes a new advisory data session for the specified
// distro and returns a reference to the session. This call will retrieve the
// data and manage it in a local temp directory until the session is closed. The
// session should be closed by calling Close() when it is no longer needed.
func NewDataSession(ctx context.Context, opts DataSessionOptions) (*DataSession, error) {
	// create temp directory
	tempDir, err := os.MkdirTemp("", "wolfictl-advisory-data-session-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp dir: %w", err)
	}
	ds := &DataSession{
		tempDir: tempDir,
		distro:  opts.Distro,
	}

	ds.githubClient = opts.GitHubClient

	gitAuth, err := wgit.GetGitAuth(opts.Distro.Absolute.AdvisoriesHTTPSCloneURL())
	if err != nil {
		return nil, fmt.Errorf("getting git auth: %w", err)
	}

	// clone advisories repo
	repo, err := git.PlainCloneContext(ctx, tempDir, false, &git.CloneOptions{
		URL:  opts.Distro.Absolute.AdvisoriesHTTPSCloneURL(),
		Auth: gitAuth,
	})
	if err != nil {
		return nil, fmt.Errorf("cloning advisories repo: %w", err)
	}
	ds.repo = repo

	// checkout a new branch
	u := uuid.New()
	branchName := fmt.Sprintf("wolfictl-data-session-%s", u)
	ds.workingBranch = branchName
	wt, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("getting worktree: %w", err)
	}
	err = wt.Checkout(&git.CheckoutOptions{
		Branch: plumbing.NewBranchReferenceName(branchName),
		Create: true,
	})
	if err != nil {
		return nil, fmt.Errorf("checking out new branch: %w", err)
	}

	// index advisory documents
	index, err := v2.NewIndex(ctx, rwos.DirFS(tempDir))
	if err != nil {
		return nil, fmt.Errorf("indexing advisory documents: %w", err)
	}
	ds.index = index

	return ds, nil
}

// Close closes the advisory data session and cleans up any temporary data that
// was downloaded.
func (ds DataSession) Close() error {
	return os.RemoveAll(ds.tempDir)
}

// Create creates a new advisory within the context of the data session.
func (ds *DataSession) Create(ctx context.Context, req Request) error {
	err := Create(ctx, req, CreateOptions{
		AdvisoryDocs: ds.index,
	})
	if err != nil {
		return fmt.Errorf("creating advisory: %w", err)
	}

	err = ds.commit(ctx, req, "create")
	if err != nil {
		return fmt.Errorf("committing advisory creation: %w", err)
	}

	ds.modified = true
	ds.modifiedPackages = append(ds.modifiedPackages, req.Package)

	return nil
}

// Update updates an existing advisory within the context of the data session.
func (ds *DataSession) Update(ctx context.Context, req Request) error {
	err := Update(ctx, req, UpdateOptions{
		AdvisoryDocs: ds.index,
	})
	if err != nil {
		return fmt.Errorf("updating advisory: %w", err)
	}

	err = ds.commit(ctx, req, "update")
	if err != nil {
		return fmt.Errorf("committing advisory update: %w", err)
	}

	ds.modified = true
	ds.modifiedPackages = append(ds.modifiedPackages, req.Package)

	return nil
}

// Append creates a new event for an advisory if the advisory already exists, or
// creates a new advisory with the event if the advisory does not already exist.
func (ds *DataSession) Append(ctx context.Context, req Request) error {
	packageSelection := ds.index.Select().WhereName(req.Package)
	if packageSelection.Len() == 0 {
		return ds.Create(ctx, req)
	}

	if _, exists := packageSelection.Configurations()[0].Advisories.GetByVulnerability(req.VulnerabilityID); !exists {
		return ds.Create(ctx, req)
	}

	return ds.Update(ctx, req)
}

// Dir returns the path to the temporary directory where the session's advisory
// data is currently stored.
func (ds DataSession) Dir() string {
	return ds.tempDir
}

// Index returns the index of advisory documents for the session.
func (ds DataSession) Index() *configs.Index[v2.Document] {
	return ds.index
}

// Modified returns true if any changes have been made to the advisory data
// during the session.
func (ds DataSession) Modified() bool {
	return ds.modified
}

// Push pushes the changes made during the session to the remote advisories
// repository.
func (ds DataSession) Push(ctx context.Context) error {
	gitAuth, err := wgit.GetGitAuth(ds.distro.Absolute.AdvisoriesHTTPSCloneURL())
	if err != nil {
		return fmt.Errorf("getting git auth: %w", err)
	}

	err = ds.repo.PushContext(ctx, &git.PushOptions{
		RemoteURL: ds.distro.Absolute.AdvisoriesHTTPSCloneURL(),
		Auth:      gitAuth,
	})
	if err != nil {
		return fmt.Errorf("pushing changes: %w", err)
	}

	return nil
}

// OpenPullRequest opens a pull request for the changes made during the session.
func (ds DataSession) OpenPullRequest(ctx context.Context) (*PullRequest, error) {
	slices.Sort(ds.modifiedPackages)
	compact := slices.Compact(ds.modifiedPackages)
	newPullRequest := github.NewPullRequest{
		Title:               github.String(fmt.Sprintf("Add advisory data for %s", strings.Join(compact, ", "))),
		Body:                github.String(pullRequestBody),
		Head:                github.String(ds.workingBranch),
		Base:                github.String("main"),
		MaintainerCanModify: github.Bool(true),
	}

	pullRequest, _, err := ds.githubClient.PullRequests.Create(
		ctx,
		ds.distro.Absolute.DistroRepoOwner,
		ds.distro.Absolute.DistroAdvisoriesRepo,
		&newPullRequest,
	)
	if err != nil {
		return nil, fmt.Errorf("creating pull request on GitHub: %w", err)
	}

	pr := PullRequest{
		URL: pullRequest.GetHTMLURL(),
	}

	return &pr, nil
}

const pullRequestBody = "This PR was created using the `wolfictl adv guide` command."

type PullRequest struct {
	URL string
}

// commit creates a commit in the advisory repo for the specified operation.
func (ds DataSession) commit(_ context.Context, req Request, operation string) error {
	commitMessage := fmt.Sprintf(
		"%s: %s advisory %s",
		req.Package,
		operation,
		req.VulnerabilityID,
	)

	wt, err := ds.repo.Worktree()
	if err != nil {
		return fmt.Errorf("getting worktree: %w", err)
	}
	err = wt.AddGlob(fmt.Sprintf("%s.advisories.yaml", req.Package))
	if err != nil {
		return fmt.Errorf("staging changes: %w", err)
	}
	_, err = wt.Commit(commitMessage, &git.CommitOptions{})
	if err != nil {
		return fmt.Errorf("creating commit: %w", err)
	}

	return nil
}
