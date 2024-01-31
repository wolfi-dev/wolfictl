package ruby

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"

	"github.com/google/go-github/v58/github"
	"github.com/hashicorp/go-version"

	"github.com/wolfi-dev/wolfictl/pkg/gh"
)

// CheckUpgrade attempts to find a gemspec for a given ruby gem and tries to
// extract the required_ruby_version field from it. The required_ruby_version
// should provide a set of constraints restricting the version of ruby a gem
// can run on. CheckUpgrade simply tries to make sure the given RubyUpdateVersion
// is within those constraints.
func (o *Options) CheckUpgrade(ctx context.Context, pkg *Package) error {
	// find the gemspec in the repository
	gemspec, err := o.findGemspec(ctx, pkg)
	if err != nil {
		return fmt.Errorf("finding gemspec in repository: %w", err)
	}

	// download (and cache) the gemspec file
	gemspecFile, err := o.fetchFile(ctx, pkg, gemspec)
	if err != nil {
		return fmt.Errorf("downloading gemspec: %w", err)
	}

	// search the gemspec for version constraints
	return o.checkVersionConstraint(gemspecFile)
}

// findGemspec searches a given Github repository for a file named *.gemspec. It
// searches for the file from the branch or tag specified in the melange yaml.
func (o *Options) findGemspec(ctx context.Context, pkg *Package) (string, error) {
	client := github.NewClient(o.Client.Client)
	gitOpts := gh.GitOptions{
		GithubClient: client,
	}

	directoryContents, err := gitOpts.ListRepositoryFiles(ctx, pkg.Repo.Organisation, pkg.Repo.Name, "", pkg.Ref)
	if err != nil {
		return "", err
	}

	for _, file := range directoryContents {
		if strings.HasSuffix(file.GetName(), gemspecSuffix) {
			return file.GetName(), nil
		}
	}
	return "", fmt.Errorf("could not find gemspec file in repo")
}

// cachedGemspecPath returns the path to a cached gemspec file
func (o *Options) cachedGemspecPath(pkg *Package, gemspec string) string {
	return path.Join(rubyCacheDirectory, pkg.Name, fmt.Sprintf("%s-%s", pkg.Ref, gemspec))
}

// fetchFile downloads a given file (in this case a gemspec) from a given
// Github repository. It downloads the file from the branch or tag specified
// in the melange yaml. It will cache the file using the name of the file and
// the branch or tag specified in the melange yaml.
func (o *Options) fetchFile(ctx context.Context, pkg *Package, file string) (string, error) {
	logger := log.New(log.Writer(), "wolfictl ruby check-upgrade: ", log.LstdFlags|log.Lmsgprefix)
	cachedPath := o.cachedGemspecPath(pkg, file)
	cached, err := os.Open(cachedPath)
	if err != nil || o.NoCache {
		client := github.NewClient(o.Client.Client)
		gitOpts := gh.GitOptions{
			GithubClient: client,
			Logger:       logger,
		}

		fileContent, err := gitOpts.RepositoryFilesContents(ctx, pkg.Repo.Organisation, pkg.Repo.Name, file, pkg.Ref)
		if err != nil {
			return "", err
		}

		// Decode the base64-encoded content
		decodedContent, err := base64.StdEncoding.DecodeString(*fileContent.Content)
		if err != nil {
			return "", fmt.Errorf("error decoding file content: %w", err)
		}

		err = os.MkdirAll(path.Dir(cachedPath), 0o755)
		if err != nil {
			return "", fmt.Errorf("failed to create cache directory: %w", err)
		}

		cached, err = os.Create(cachedPath)
		if err != nil {
			return "", fmt.Errorf("failed to create cache file: %w", err)
		}

		_, err = cached.Write(decodedContent)
		if err != nil {
			return "", fmt.Errorf("failed to write cache file: %w", err)
		}
	}
	defer cached.Close()
	return cachedPath, nil
}

// checkVersionConstraint takes a gemspec and extracts the version constraints
// and checks them against the RubyUpdateVersion. This function attempts to use
// inline ruby to determine if the version is within constraints. If ruby is
// not installed on the system then the terraform go-version package is used as
// it has very similar version constraints. The inline ruby is the preferred
// method in case something changes (highly unlikely).
//
// NOTE: If there is no required_ruby_version found in the gemspec then we
//
//	assume there is no limit.
func (o *Options) checkVersionConstraint(gemspecFile string) error {
	cached, err := os.Open(gemspecFile)
	if err != nil {
		return fmt.Errorf("opening gemspec file: %w", err)
	}
	versionLine := ""
	scanner := bufio.NewScanner(cached)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), requiredRubyVersionKey) {
			versionLine = scanner.Text()
			break
		}
	}

	// Could not find required_ruby_version in gemspec, assuming no constraint
	if versionLine == "" {
		return nil
	}

	pattern := `["']([^"']+)["']`
	re := regexp.MustCompile(pattern)
	groups := re.FindAllStringSubmatch(versionLine, -1)

	versionConstraints := []string{}
	for _, group := range groups {
		versionConstraints = append(versionConstraints, group[1])
	}

	if len(versionConstraints) < 1 {
		return fmt.Errorf("could not extract %s from gemspec", requiredRubyVersionKey)
	}

	rubyPath, err := exec.LookPath("ruby")
	if err == nil { // Call ruby to do the comparison
		// Need to construct a list of version constraints to pass
		// to the ruby call. It should end up like this: ['>= 2.6', '< 4']
		constraint := fmt.Sprintf("['%s']", strings.Join(versionConstraints, "', '"))

		cmdArr := []string{
			"-e",
			fmt.Sprintf("Gem::Dependency.new('', %s).match?('', '%s') ? exit : abort('')", constraint, o.RubyUpdateVersion),
		}
		cmd := exec.Command(rubyPath, cmdArr...)
		_, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("ruby version comparison failed")
		}
	} else { // If ruby doesn't exist on the system do the version comparison ourselves
		// Terraform has the same version comparison operators as ruby so we
		// just use the terraform library to do the comparison
		v1, err := version.NewVersion(o.RubyUpdateVersion)
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
