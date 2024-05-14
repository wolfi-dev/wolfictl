package git

import (
	"fmt"
	"sort"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/hashicorp/go-version"
	wolfiversions "github.com/wolfi-dev/wolfictl/pkg/versions"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
)

func CreateTag(dir, tag string) error {
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

	tagOptions.Tagger = GetGitAuthorSignature()

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

	gitAuth, err := GetGitAuth(remoteURL)
	if err != nil {
		return fmt.Errorf("failed to get git auth: %w", err)
	}

	po := &git.PushOptions{
		RemoteName: "origin",
		RemoteURL:  remoteURL,
		RefSpecs:   []config.RefSpec{config.RefSpec(fmt.Sprintf("refs/tags/%s:refs/tags/%s", tagName, tagName))},
		Auth:       gitAuth,
	}

	err = r.Push(po)

	if err != nil {
		if err == git.NoErrAlreadyUpToDate {
			return nil
		}
		return fmt.Errorf("failed to push tag: %w", err)
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
			return fmt.Errorf("failed to create new version from tag %q: %w", t.Name().Short(), err)
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
