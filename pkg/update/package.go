package update

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	advisoryconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/advisory"
	rwfsOS "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"

	"github.com/google/go-github/v50/github"

	"github.com/openvex/go-vex/pkg/vex"

	"github.com/wolfi-dev/wolfictl/pkg/advisory"

	"github.com/pkg/errors"

	"github.com/hashicorp/go-version"

	wolfigit "github.com/wolfi-dev/wolfictl/pkg/git"

	"github.com/go-git/go-git/v5"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"

	wolfihttp "github.com/wolfi-dev/wolfictl/pkg/http"
	"github.com/wolfi-dev/wolfictl/pkg/melange"
)

type PackageOptions struct {
	PackageName           string
	PackageConfig         map[string]*melange.Packages
	PullRequestBaseBranch string
	TargetRepo            string
	Version               string
	Epoch                 string
	Advisories            bool
	DryRun                bool
	UseGitSign            bool
	Logger                *log.Logger
	GithubClient          *github.Client
}

// NewPackageOptions initialise clients
func NewPackageOptions() PackageOptions {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)

	ratelimit := &wolfihttp.RLHTTPClient{
		Client: oauth2.NewClient(context.Background(), ts),

		// 1 request every (n) second(s) to avoid DOS'ing server. https://docs.github.com/en/rest/guides/best-practices-for-integrators?apiVersion=2022-11-28#dealing-with-secondary-rate-limits
		Ratelimiter: rate.NewLimiter(rate.Every(3*time.Second), 1),
	}

	options := PackageOptions{
		GithubClient: github.NewClient(ratelimit.Client),
		Logger:       log.New(log.Writer(), "wolfictl update: ", log.LstdFlags|log.Lmsgprefix),
	}

	return options
}

func (o *PackageOptions) UpdatePackageCmd(ctx context.Context) error {
	// clone the melange config git repo into a temp folder so we can work with it
	tempDir, err := os.MkdirTemp("", "wolfictl")
	if err != nil {
		return fmt.Errorf("failed to create temporary folder to clone package configs into: %w", err)
	}
	if o.DryRun {
		o.Logger.Printf("using working directory %s", tempDir)
	} else {
		defer os.Remove(tempDir)
	}

	cloneOpts := &git.CloneOptions{
		URL:               o.TargetRepo,
		Progress:          os.Stdout,
		RecurseSubmodules: git.NoRecurseSubmodules,
		Auth:              wolfigit.GetGitAuth(),
		Depth:             1,
	}

	repo, err := git.PlainClone(tempDir, false, cloneOpts)
	if err != nil {
		return fmt.Errorf("failed to clone repository %s into %s: %w", o.TargetRepo, tempDir, err)
	}

	// first, let's get the melange package(s) from the target git repo, that we want to check for updates
	o.PackageConfig, err = melange.ReadPackageConfigs([]string{o.PackageName}, tempDir)
	if err != nil {
		return fmt.Errorf("failed to get package config for package name %s: %w", o.PackageName, err)
	}

	uo := New()
	uo.PackageConfigs = o.PackageConfig
	uo.DryRun = o.DryRun
	uo.PullRequestBaseBranch = o.PullRequestBaseBranch
	uo.PullRequestTitle = "%s/%s package update"
	uo.UseGitSign = o.UseGitSign

	// let's work on a branch when updating package versions, so we can create a PR from that branch later
	ref, err := uo.createBranch(repo)
	if err != nil {
		return fmt.Errorf("failed to switch to working git branch: %w", err)
	}

	// optionally update advisories based on commit since the previous release
	if o.Advisories {
		err := o.updateAdvisories(repo)
		if err != nil {
			return fmt.Errorf("failed to update secfixes: %w", err)
		}
	}

	// update melange configs in our cloned git repository with any new package versions
	v := strings.TrimPrefix(o.Version, "v")

	nvr := NewVersionResults{
		Version: v,
	}
	errorMessage, err := uo.updateGitPackage(ctx, repo, o.PackageName, nvr, ref)
	if err != nil {
		return fmt.Errorf("failed to update package in git repository: %w", err)
	}
	if errorMessage != "" {
		return errors.New(errorMessage)
	}
	return nil
}

// if we are executing the update command in a git repository then check for CVE fixes
func (o *PackageOptions) updateAdvisories(repo *git.Repository) error {
	currentDir, err := os.Getwd()
	if err != nil {
		return err
	}
	gitURL, err := wolfigit.GetRemoteURLFromDir(currentDir)
	if err != nil {
		return err
	}
	// checkout repo into tmp dir so we know we are working on a clean HEAD
	cloneOpts := &git.CloneOptions{
		URL:               gitURL.RawURL,
		RecurseSubmodules: git.NoRecurseSubmodules,
		Auth:              wolfigit.GetGitAuth(),
		Tags:              git.AllTags,
		Depth:             20,
	}

	tempDir, err := os.MkdirTemp("", "wolfictl")
	if err != nil {
		return fmt.Errorf("failed to create temporary folder to clone package configs into: %w", err)
	}

	_, err = git.PlainClone(tempDir, false, cloneOpts)
	if err != nil {
		return fmt.Errorf("failed to clone repository %s into %s: %w", o.TargetRepo, tempDir, err)
	}

	if _, err := os.Stat(filepath.Join(tempDir, ".git")); os.IsNotExist(err) {
		o.Logger.Println("skip sec fixes as we are not running update from a git repo")
		return nil
	}

	// ignore errors getting previous tags as most likely there's no existing release so should check all commits
	previous, err := wolfigit.GetVersionFromTag(tempDir, 2)
	if err != nil {
		o.Logger.Println("no previous tag found so checking all commits for sec fixes")
	}

	// get list of commits between the previous tag and current tag
	cveFixes, err := o.getFixesCVEList(tempDir, previous)
	if err != nil {
		return errors.Wrapf(err, "failed to get CVE list from commits between tags %s and %s", previous, o.Version)
	}

	if len(cveFixes) == 0 {
		o.Logger.Printf("no fixes: CVE### comments found from commits between tags %s and %s, skip creating sec fix advisories\n", previous.Original(), o.Version)
		return nil
	}
	// run the equivalent of `wolfictl advisory create ./foo.melange.yaml --vuln 'CVE-2022-31130' --status 'fixed' --fixed-version '7.5.17-r1'`
	for _, fixComment := range cveFixes {
		o.Logger.Printf("adding advisory for %s\n", fixComment)
		err = o.createAdvisories(fixComment)
		if err != nil {
			return errors.Wrapf(err, "failed to create advisory for CVE list from commits between previous tag, %s", strings.Join(cveFixes, " "))
		}
	}

	return o.addCommit(repo, cveFixes)
}

// getFixesCVEList returns a list of CVEs fixed in the latest release based on commit messages i.e. fixes: CVE###
func (o *PackageOptions) getFixesCVEList(dir string, previous *version.Version) ([]string, error) {
	var fixedCVEs []string

	tagRamge := ""
	if previous != nil {
		tagRamge = fmt.Sprintf("%s...%s", previous.Original(), o.Version)
	}

	o.Logger.Printf("git log --no-merges %s", tagRamge)

	cmd := exec.Command("git", "log", "--no-merges", tagRamge)
	cmd.Dir = dir
	rs, err := cmd.Output()
	if err != nil {
		return fixedCVEs, errors.Wrapf(err, "failed to get output from git log %s", tagRamge)
	}

	// convert to string as dealing with bytes results in a 3 dimensional array, hard to debug
	//nolint:gocritic
	gitLog := string(rs[:])

	o.Logger.Printf("result: %s", gitLog)

	// parse commit comments for `fixes: CVE###`, (?i) to ignore case
	r := regexp.MustCompile(`(?i)fixes: CVE-*[0-9]\d+-*[0-9]?\d+`)

	cves := r.FindAllStringSubmatch(gitLog, -1)
	for _, commitCVEs := range cves {
		for _, cve := range commitCVEs {
			// make sure formatting in sec fixes and advisories are uppercase
			cve = strings.ToUpper(cve)

			// strip the fixes: comment as we're just interested in the CVEs
			cve = strings.TrimPrefix(cve, "FIXES: ")

			fixedCVEs = append(fixedCVEs, cve)
		}
	}

	return fixedCVEs, nil
}

func (o *PackageOptions) createAdvisories(vuln string) error {
	p := o.PackageConfig[o.PackageName]
	fullFilePath := filepath.Join(p.Dir, p.Filename)

	fsys := rwfsOS.DirFS("/")
	advisoryCfgs, err := advisoryconfigs.NewIndexFromPaths(fsys, fullFilePath)
	if err != nil {
		return errors.Wrapf(err, "failed to get new index for package %s config file %s", o.PackageName, p.Filename)
	}

	req := o.request(vuln)
	if err := req.Validate(); err != nil {
		return err
	}

	err = advisory.Create(req, advisory.CreateOptions{
		AdvisoryCfgs: advisoryCfgs,
	})
	if err != nil {
		return err
	}
	return nil
}

func (o *PackageOptions) request(vuln string) advisory.Request {
	fixedVersion := fmt.Sprintf("%s-r%s", strings.TrimPrefix(o.Version, "v"), o.Epoch)

	return advisory.Request{
		Package:       o.PackageName,
		Vulnerability: vuln,
		Status:        vex.StatusFixed,
		Timestamp:     time.Now(),
		FixedVersion:  fixedVersion,
	}
}

// func (o *PackageOptions) getFixedReleaseURL() (string, error) {
//	currentDir, err := os.Getwd()
//	if err != nil {
//		return "", err
//	}
//
//	r, err := git.PlainOpen(currentDir)
//	if err != nil {
//		return "", err
//	}
//
//	remoteURL, err := wolfigit.GetRemoteURL(r)
//	if err != nil {
//		return "", err
//	}
//
//	releaseOpts := gh.ReleaseOptions{
//		GithubClient: o.GithubClient,
//	}
//	releaseURL, err := releaseOpts.GetReleaseURL(remoteURL.Organisation, remoteURL.Name, o.Version)
//	if err != nil {
//		return "", err
//	}
//	return releaseURL, nil
// }

func (o *PackageOptions) addCommit(repo *git.Repository, fixes []string) error {
	wt, err := repo.Worktree()
	if err != nil {
		return err
	}

	p, ok := o.PackageConfig[o.PackageName]
	if !ok {
		return fmt.Errorf("no package config found for package name %s", o.PackageName)
	}

	_, err = wt.Add(p.Filename)
	if err != nil {
		return err
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return err
	}

	commitMessage := fmt.Sprintf("add advisory and secfixes %s", strings.Join(fixes, " "))

	commitOpts := &git.CommitOptions{}
	commitOpts.Author = wolfigit.GetGitAuthorSignature()

	if o.UseGitSign {
		err := wolfigit.SetGitSignOptions(wt.Filesystem.Root())
		if err != nil {
			return fmt.Errorf("failed to set git config: %w", err)
		}

		// maybe we change this when https://github.com/go-git/go-git/issues/400 is implemented
		cmd := exec.Command("git", "commit", "-sm", commitMessage)
		cmd.Dir = p.Dir
		rs, err := cmd.Output()
		if err != nil {
			return errors.Wrapf(err, "failed to git sign commit %s", rs)
		}
	} else {
		if _, err = worktree.Commit(commitMessage, commitOpts); err != nil {
			return fmt.Errorf("failed to git commit: %w", err)
		}
	}

	return nil
}
