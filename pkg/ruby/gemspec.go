package ruby

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"

	"github.com/adrg/xdg"
	"github.com/google/go-github/v55/github"
	"github.com/hashicorp/go-version"

	"github.com/wolfi-dev/wolfictl/pkg/gh"
	wgit "github.com/wolfi-dev/wolfictl/pkg/git"
)

const (
	requiredRubyVersionKey = "required_ruby_version"
)

func (rc *RubyRepoContext) Gemspec() (string, error) {
	// find the Gemspec
	gemspec, err := rc.findGemspec()
	if err != nil {
		fmt.Printf("finding gemspec: %s\n", err)
		return "", nil
		// return "", fmt.Errorf("finding gemspec: %w", err)
	}

	// download the Gemspec
	err = rc.fetchFile(gemspec)
	if err != nil {
		return "", fmt.Errorf("downloading gemspec: %w", err)
	}

	// search the gemspec for version constraints
	// TODO
	return "", nil
}

func (rc *RubyRepoContext) findGemspec() (string, error) {
	ctx := context.Background()
	client := github.NewClient(rc.Client.Client)
	gitOpts := gh.GitOptions{
		GithubClient: client,
	}

	gitURL, err := wgit.ParseGitURL(rc.Pkg.Repo)
	if err != nil {
		return "", err
	}

	directoryContents, err := gitOpts.ListRepositoryFiles(ctx, gitURL.Organisation, gitURL.Name, "", rc.Pkg.Ref)
	if err != nil {
		return "", err
	}

	for _, file := range directoryContents {
		if strings.HasSuffix(file.GetName(), gemspecSuffix) {
			return file.GetName(), nil
		}
	}
	return "", fmt.Errorf("Could not find gemspec")
}

func (rc *RubyRepoContext) fetchFile(file string) error {
	cachedPath, err := rc.cachedGemspecPath(file)
	if err != nil {
		return fmt.Errorf("failed to get gemspec cache path")
	}
	cached, err := os.Open(cachedPath)
	if err != nil {
		ctx := context.Background()

		gitURL, err := wgit.ParseGitURL(rc.Pkg.Repo)
		if err != nil {
			return err
		}

		client := github.NewClient(rc.Client.Client)
		gitOpts := gh.GitOptions{
			GithubClient: client,
		}
		fileContent, err := gitOpts.RepositoryFilesContents(ctx, gitURL.Organisation, gitURL.Name, file, rc.Pkg.Ref)
		if err != nil {
			return err
		}

		// Decode the base64-encoded content
		decodedContent, err := base64.StdEncoding.DecodeString(*fileContent.Content)
		if err != nil {
			return fmt.Errorf("Error decoding file content: %w", err)
		}

		err = os.MkdirAll(path.Dir(cachedPath), 0o755)
		if err != nil {
			return fmt.Errorf("failed to create cache directory: %w", err)
		}

		cached, err = os.Create(cachedPath)
		if err != nil {
			return fmt.Errorf("failed to create cache file: %w", err)
		}

		_, err = cached.Write(decodedContent)
		if err != nil {
			return fmt.Errorf("failed to write cache file: %w", err)
		}

	}
	defer cached.Close()

	versionLine := ""
	scanner := bufio.NewScanner(cached)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), requiredRubyVersionKey) {
			versionLine = scanner.Text()
			break
		}
	}
	if versionLine == "" {
		fmt.Printf("Could not find %s, assuming no constraint\n", requiredRubyVersionKey)
		return nil
	}

	pattern := `["']([^"']+)["']`
	re := regexp.MustCompile(pattern)
	groups := re.FindAllStringSubmatch(string(versionLine), -1)

	versionConstraints := []string{}
	for _, group := range groups {
		versionConstraints = append(versionConstraints, group[1])
	}
	return rc.checkVersionConstraint(versionConstraints)
}

func (rc *RubyRepoContext) checkVersionConstraint(versionConstraints []string) error {
	if len(versionConstraints) < 1 {
		fmt.Printf("Required Ruby Version not found in the gemspec.\n")
		return nil
		// return fmt.Errorf("Required Ruby Version not found in the gemspec.")
	}

	rubyPath, err := exec.LookPath("ruby")
	if err == nil { // Call ruby to do the comparison
		// Need to construct a list of version constraints to pass
		// to the ruby call. It should end up like this: ['>= 2.6', '< 4']
		constraint := "["
		for i, c := range versionConstraints {
			constraint += fmt.Sprintf("'%s'", c)
			if i != len(versionConstraints)-1 {
				constraint += ", "
			}
		}
		constraint += "]"

		cmdArr := []string{
			"-e",
			fmt.Sprintf("Gem::Dependency.new('', %s).match?('', '%s') ? exit : abort('')", constraint, rc.UpdateVersion),
		}
		cmd := exec.Command(rubyPath, cmdArr...)
		_, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("ruby version comparison failed")
		}
	} else { // If ruby doesn't exist on the system do the version comparison ourselves
		// Terraform has the same version comparison operators as ruby so we
		// just use the terraform library to do the comparison
		v1, err := version.NewVersion(rc.UpdateVersion)
		if err != nil {
			return fmt.Errorf("converting ruby update version: %w", err)
		}

		constraints, err := version.NewConstraint(strings.Join(versionConstraints, ", "))
		if err != nil {
			return fmt.Errorf("converting ruby version constraint: %w", err)
		}

		if !constraints.Check(v1) {
			return fmt.Errorf("ruby version comparison failed")
		}
	}
	return nil
}

var rubyCacheDirectory = path.Join(xdg.CacheHome, "wolfictl", "ruby")

func (rc *RubyRepoContext) cachedGemspecPath(gemspec string) (string, error) {
	return path.Join(rubyCacheDirectory, "gemspecs", fmt.Sprintf("%s-%s", rc.Pkg.Ref, gemspec)), nil
}
