package gh

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	http2 "github.com/wolfi-dev/wolfictl/pkg/http"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"

	"github.com/google/go-github/v55/github"

	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	wolfigit "github.com/wolfi-dev/wolfictl/pkg/git"

	"github.com/go-git/go-git/v5"
)

type ReleaseOptions struct {
	GithubClient             *github.Client
	Logger                   *log.Logger
	BumpMajor                bool
	BumpMinor                bool
	BumpPatch                bool
	BumpPrereleaseWithPrefix string
	Dir                      string
}

func NewReleaseOptions() ReleaseOptions {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)

	ratelimit := &http2.RLHTTPClient{
		Client: oauth2.NewClient(context.Background(), ts),

		// 1 request every (n) second(s) to avoid DOS'ing server. https://docs.github.com/en/rest/guides/best-practices-for-integrators?apiVersion=2022-11-28#dealing-with-secondary-rate-limits
		Ratelimiter: rate.NewLimiter(rate.Every(3*time.Second), 1),
	}

	return ReleaseOptions{
		GithubClient: github.NewClient(ratelimit.Client),
		Logger:       log.New(log.Writer(), "wolfictl gh release: ", log.LstdFlags|log.Lmsgprefix),
	}
}

const defaultStartVersion = "v0.0.0"

// Release will create a new GitHub release
func (o ReleaseOptions) Release() error {
	// get the latest git tag
	current, err := wolfigit.GetVersionFromTag(o.Dir, 1)
	if current == nil || err != nil {
		current, err = version.NewVersion(defaultStartVersion)
		if err != nil {
			return err
		}
	}

	o.Logger.Printf("current latest version tag is %s", current.Original())

	// increment
	next, err := o.bumpReleaseVersion(current)
	if err != nil {
		return errors.Wrapf(err, "failed to bump current version %s", current.Original())
	}

	// create new tag + GitHub release
	err = wolfigit.CreateTag(o.Dir, next.Original())
	if err != nil {
		return errors.Wrapf(err, "failed to create tag %s", next.Original())
	}

	// push new tag
	err = wolfigit.PushTag(o.Dir, next.Original())
	if err != nil {
		return err
	}

	// create the GitHub release
	err = o.createGitHubRelease(next.Original())
	if err != nil {
		return err
	}

	fmt.Printf("::set-output name=new_version::%s\n", next.Original())
	return nil
}

// bumpReleaseVersion will increment parts of a new release version based on flags supplied when running the CLI command
func (o ReleaseOptions) bumpReleaseVersion(current *version.Version) (*version.Version, error) {
	prefix := ""
	if strings.HasPrefix(current.Original(), "v") {
		prefix = "v"
	}

	major := current.Segments()[0]
	minor := current.Segments()[1]
	patch := current.Segments()[2]

	if o.BumpMajor {
		major++
	}

	if o.BumpMinor {
		minor++
	}

	if o.BumpPatch {
		patch++
	}

	newPrerelease := ""
	if o.BumpPrereleaseWithPrefix != "" {
		prerelease := current.Prerelease()

		// if no existing prerelease automatically bump the patch as semver will say existing patch version is newer than our new prerelease
		if prerelease == "" {
			newPrerelease = fmt.Sprintf("%s%d", o.BumpPrereleaseWithPrefix, 1)

			// override bumping patch if no existing prerelease
			if !o.BumpPatch {
				patch++
			}
		} else {
			preReleaseVersion := strings.TrimPrefix(prerelease, o.BumpPrereleaseWithPrefix)

			i, err := strconv.Atoi(preReleaseVersion)
			if err != nil {
				return nil, err
			}
			newPrerelease = fmt.Sprintf("%s%d", o.BumpPrereleaseWithPrefix, i+1)
		}
	}

	// this needs to be in the form 1.2.3rc2 and not 1.2.3-rc2 as apk doesn't recognise the latter as newer than a previous prerelease like 1.2.3-rc1
	newVersion := fmt.Sprintf("%s%d.%d.%d%s", prefix, major, minor, patch, newPrerelease)

	return version.NewVersion(newVersion)
}

// createGitHubRelease creates a new release on GitHub
func (o ReleaseOptions) createGitHubRelease(v string) error {
	repo, err := git.PlainOpen(o.Dir)
	if err != nil {
		return err
	}

	gitURL, err := wolfigit.GetRemoteURL(repo)
	if err != nil {
		return fmt.Errorf("failed to find git origin URL: %w", err)
	}

	input := &github.RepositoryRelease{
		Name:    github.String(v),
		TagName: github.String(v),
	}

	ctx := context.Background()
	release, _, err := o.GithubClient.Repositories.CreateRelease(ctx, gitURL.Organisation, gitURL.Name, input)
	if err != nil {
		return err
	}

	o.Logger.Printf("successfully created new release %s", *release.HTMLURL)
	return nil
}

func (o ReleaseOptions) GetReleaseURL(owner, repoName, v string) (string, error) {
	ctx := context.Background()
	release, _, err := o.GithubClient.Repositories.GetReleaseByTag(ctx, owner, repoName, v)
	if err != nil {
		return "", errors.Wrapf(err, "failed to get github release for %s/%s tag %s", owner, repoName, v)
	}
	return *release.HTMLURL, nil
}
