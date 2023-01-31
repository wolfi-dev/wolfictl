package gh

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing/object"

	http2 "github.com/wolfi-dev/wolfictl/pkg/http"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"

	"github.com/google/go-github/v48/github"

	"github.com/pkg/errors"
	wolfigit "github.com/wolfi-dev/wolfictl/pkg/git"
	wolfiversions "github.com/wolfi-dev/wolfictl/pkg/versions"

	"github.com/hashicorp/go-version"

	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"

	"github.com/go-git/go-git/v5"
)

const defaultStartVersion = "v0.0.0"

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

// Release will create a new GitHub release
func (o ReleaseOptions) Release() error {
	// get the latest git tag
	current, err := o.getCurrentVersionFromTag()
	if err != nil {
		return errors.Wrapf(err, "failed to get current version from tag in dir %s", o.Dir)
	}

	o.Logger.Printf("current latest version tag is %s", current.Original())

	// increment
	next, err := o.bumpReleaseVersion(current)
	if err != nil {
		return errors.Wrapf(err, "failed to bump current version %s", current.Original())
	}

	// create new tag + GitHub release
	err = o.createTag(next.Original(), "", "")
	if err != nil {
		return errors.Wrapf(err, "failed to create tag %s", next.Original())
	}

	// push new tag
	err = o.pushTag(next.Original())
	if err != nil {
		return err
	}

	return o.createGitHubRelease(next.Original())
}

func (o ReleaseOptions) getCurrentVersionFromTag() (*version.Version, error) {
	r, err := git.PlainOpen(o.Dir)
	if err != nil {
		return nil, err
	}

	tagRefs, err := r.Tags()
	if err != nil {
		return nil, err
	}

	// collect all tags
	var versions []*version.Version

	err = tagRefs.ForEach(func(t *plumbing.Reference) error {
		releaseVersionSemver, err := version.NewVersion(t.Name().Short())
		if err != nil {
			return errors.Wrapf(err, "failed to create new version from tag %s", t.Name().Short())
		}
		versions = append(versions, releaseVersionSemver)
		return nil
	})
	if err != nil {
		return nil, err
	}

	// get the latest tag, maybe need to sort?
	sort.Sort(wolfiversions.ByLatest(versions))
	var latest *version.Version
	if len(versions) == 0 {
		latest, err = version.NewVersion(defaultStartVersion)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create new version from tag %s", defaultStartVersion)
		}
	} else {
		// get the last tag
		latest = versions[len(versions)-1]
	}
	return latest, nil
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

func (o ReleaseOptions) createTag(tag, overrideGitName, overrideGitEmail string) error {
	r, err := git.PlainOpen(o.Dir)
	if err != nil {
		return err
	}

	o.Logger.Printf("creating tag %s", tag)
	h, err := r.Head()
	if err != nil {
		return err
	}

	tagOptions := &git.CreateTagOptions{
		Message: tag,
	}
	// override default git config tagger info
	if overrideGitName != "" && overrideGitEmail != "" {
		o.Logger.Printf("overriding default git tagger config with name %s: email: %s", overrideGitName, overrideGitEmail)
		tagOptions.Tagger = &object.Signature{
			Name:  overrideGitName,
			Email: overrideGitEmail,
			When:  time.Now(),
		}
	}

	_, err = r.CreateTag(tag, h.Hash(), tagOptions)

	return err
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

func (o ReleaseOptions) pushTag(tagName string) error {
	r, err := git.PlainOpen(o.Dir)
	if err != nil {
		return err
	}

	// force remote URL to be https, using git@ requires ssh keys and we default to using basic auth
	remote, err := r.Remote("origin")
	if err != nil {
		return err
	}
	gitURL, err := wolfigit.ParseGitURL(remote.Config().URLs[0])
	if err != nil {
		return err
	}
	remoteURL := fmt.Sprintf("https://github.com/%s/%s.git", gitURL.Organisation, gitURL.Name)

	po := &git.PushOptions{
		RemoteName: "origin",
		RemoteURL:  remoteURL,
		RefSpecs:   []config.RefSpec{config.RefSpec(fmt.Sprintf("refs/tags/%s:refs/tags/%s", tagName, tagName))},
		Auth:       wolfigit.GetGitAuth(),
	}

	err = r.Push(po)

	if err != nil {
		if err == git.NoErrAlreadyUpToDate {
			o.Logger.Println("origin remote was up to date, no push done")
			return nil
		}
		return errors.Wrapf(err, "failed to push tag")
	}

	return nil
}
