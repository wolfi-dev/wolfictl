package submodules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"

	"github.com/go-git/go-git/config"
	"github.com/pkg/errors"

	wgit "github.com/wolfi-dev/wolfictl/pkg/git"
)

// Update will modify a .gitmodules file and perform a `git submodule update --remote`
func Update(dir, owner, repo, version string, wt *git.Worktree) error {
	// update the .gitmodule config file
	submodules, err := updateConfigFile(dir, owner, repo, version)
	if err != nil {
		return errors.Wrap(err, "failed to update gitmodules file")
	}

	if _, err = wt.Add(".gitmodules"); err != nil {
		return fmt.Errorf("failed to git add .gitmodules: %w", err)
	}

	// git submodule update --remote
	for _, submodule := range submodules {
		err := updateSubmodules(submodule.Name, wt)
		if err != nil {
			return errors.Wrapf(err, "failed to update gitmodules")
		}

		// need to fall back to using git CLI as go-git hasn't implemented adding submodules
		// there are errors with empty dir that are references to git module shas when adding via go-git
		//nolint:gosec
		cmd := exec.Command("git", "add", submodule.Path)
		cmd.Dir = dir
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("failed to git add %s %w", submodule.Path, err)
		}
	}

	return nil
}

func updateConfigFile(dir, owner, repo, version string) (map[string]*config.Submodule, error) {
	updatedSubmodules := make(map[string]*config.Submodule)

	filename := filepath.Join(dir, ".gitmodules")
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read gitmodules file %s", filename)
	}

	cfg := config.NewModules()

	err = cfg.Unmarshal(data)
	if err != nil {
		return updatedSubmodules, err
	}

	// loop through all submodules in the .gitmodules file and set the version for any matching URLs
	for k, submodule := range cfg.Submodules {
		if strings.HasSuffix(submodule.URL, fmt.Sprintf("%s/%s.git", owner, repo)) {
			submodule.Branch = version
			updatedSubmodules[k] = submodule
		}
	}

	// modify the .gitmodules file if we have updated any submodules
	if len(updatedSubmodules) > 0 {
		info, err := os.Stat(filename)
		if err != nil {
			return updatedSubmodules, err
		}
		output, err := cfg.Marshal()
		if err != nil {
			return updatedSubmodules, err
		}
		return updatedSubmodules, os.WriteFile(filename, output, info.Mode())
	}
	return updatedSubmodules, err
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
		Auth:       wgit.GetGitAuth(),
	})

	return err
}
