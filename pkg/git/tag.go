package git

import (
	"fmt"
	"sort"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/hashicorp/go-version"
	wolfiversions "github.com/wolfi-dev/wolfictl/pkg/versions"

	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/pkg/errors"
)

func CreateTag(dir, tag, overrideGitName, overrideGitEmail string) error {
	r, err := git.PlainOpen(dir)
	if err != nil {
		return err
	}

	h, err := r.Head()
	if err != nil {
		return err
	}

	tagOptions := &git.CreateTagOptions{
		Message: tag,
	}
	// override default git config tagger info
	if overrideGitName != "" && overrideGitEmail != "" {
		tagOptions.Tagger = &object.Signature{
			Name:  overrideGitName,
			Email: overrideGitEmail,
			When:  time.Now(),
		}
	}

	_, err = r.CreateTag(tag, h.Hash(), tagOptions)

	return err
}

func PushTag(dir, tagName string) error {
	r, err := git.PlainOpen(dir)
	if err != nil {
		return err
	}

	// force remote URL to be https, using git@ requires ssh keys and we default to using basic auth
	remote, err := r.Remote("origin")
	if err != nil {
		return err
	}
	gitURL, err := ParseGitURL(remote.Config().URLs[0])
	if err != nil {
		return err
	}
	remoteURL := fmt.Sprintf("https://github.com/%s/%s.git", gitURL.Organisation, gitURL.Name)

	po := &git.PushOptions{
		RemoteName: "origin",
		RemoteURL:  remoteURL,
		RefSpecs:   []config.RefSpec{config.RefSpec(fmt.Sprintf("refs/tags/%s:refs/tags/%s", tagName, tagName))},
		Auth:       GetGitAuth(),
	}

	err = r.Push(po)

	if err != nil {
		if err == git.NoErrAlreadyUpToDate {
			return nil
		}
		return errors.Wrapf(err, "failed to push tag")
	}

	return nil
}

// GetVersionFromTag sorts git tags and returns the provided index e.g. index=1 will return the most recent tag
func GetVersionFromTag(dir string, index int) (*version.Version, error) {
	r, err := git.PlainOpen(dir)
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
	switch size := len(versions); {
	case size == 0:
		return nil, fmt.Errorf("no tags found in dir %s", dir)
	case index > size:
		return nil, fmt.Errorf("index is outside of number of tags %d", size)
	}

	return versions[len(versions)-index], nil
}
