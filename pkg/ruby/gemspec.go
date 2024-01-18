package ruby

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/adrg/xdg"
	"github.com/google/go-github/v55/github"

	"github.com/wolfi-dev/wolfictl/pkg/gh"
	wgit "github.com/wolfi-dev/wolfictl/pkg/git"
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

	// Define a regular expression pattern to match the required_ruby_version line
	pattern := `.*required_ruby_version\s*=\s*["']([^"']+)["']`

	content, err := os.ReadFile(cached.Name())
	if err != nil {
		return fmt.Errorf("reading cached gemspec: %w", err)
	}

	// Find the required_ruby_version using the regular expression
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(string(content))

	if len(matches) >= 2 {
		requiredRubyVersion := matches[1]
		fmt.Printf("Required Ruby Version : %s\n", requiredRubyVersion)
	} else {
		fmt.Println("Required Ruby Version not found in the gemspec.")
	}
	return nil
}

var rubyCacheDirectory = path.Join(xdg.CacheHome, "wolfictl", "ruby")

func (rc *RubyRepoContext) cachedGemspecPath(gemspec string) (string, error) {
	return path.Join(rubyCacheDirectory, "gemspecs", fmt.Sprintf("%s-%s", rc.Pkg.Ref, gemspec)), nil
}
