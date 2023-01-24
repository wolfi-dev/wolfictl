package submodules

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"

	"github.com/go-git/go-git/config"
	"github.com/pkg/errors"
)

// Update will modify a .gitmodules file and perform a `git submodule update --remote`
func Update(dir, owner, repo, version string, wt *git.Worktree) error {

	// update the .gitmodule config file
	submodules, err := updateConfigfile(dir, owner, repo, version)
	if err != nil {
		return errors.Wrap(err, "failed to update gitmodules file")
	}

	// git submodule update --remote
	for _, submodule := range submodules {
		err := updateSubmodules(submodule, wt)
		if err != nil {
			return errors.Wrap(err, "failed to update gitmodules")
		}
	}
	return nil
}

func updateConfigfile(dir, owner, repo, version string) ([]string, error) {
	var submodules []string
	filename := filepath.Join(dir, ".gitmodules")
	data, err := os.ReadFile(filename)

	if err != nil {
		return submodules, errors.Wrapf(err, "failed to read gitmodules file %s", filename)
	}

	cfg := config.NewModules()
	err = cfg.Unmarshal(data)

	for _, submodule := range cfg.Submodules {
		if submodule.URL == fmt.Sprintf("https://github.com/%s/%s.git", owner, repo) {
			submodules = append(submodules, submodule.Name)
			submodule.Branch = version
		}
	}
	info, err := os.Stat(filename)

	output, err := cfg.Marshal()
	return submodules, os.WriteFile(filename, output, info.Mode())

}

func updateSubmodules(submodule string, wt *git.Worktree) error {
	sub, err := wt.Submodule(submodule)
	if err != nil {
		return err
	}

	sr, err := sub.Repository()
	if err != nil {
		return err
	}

	sw, err := sr.Worktree()
	if err != nil {
		return err
	}
	err = sw.Pull(&git.PullOptions{
		RemoteName: "origin",
	})
	return nil
}
