package update

import (
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"chainguard.dev/melange/pkg/config"
	"github.com/wolfi-dev/wolfictl/pkg/melange"
	"github.com/xanzy/go-gitlab"
)

const (
	gitlabBaseURL = "https://gitlab.com"
)

type GitLabReleaseOptions struct {
	PackageConfigs map[string]*melange.Packages
	gitlabClient   *gitlab.Client
	Logger         *log.Logger

	ErrorMessages map[string]string
}
type VersionComit struct {
	Version string
	Commit  string
}

func NewGitlabReleaseOptions(packageConfigs map[string]*melange.Packages) GitLabReleaseOptions {

	token := os.Getenv("GITLAB_TOKEN")
	if token == "" {
		log.Fatalf("GITLAB_TOKEN environment variable not set")
	}

	client, err := gitlab.NewClient(token, gitlab.WithBaseURL(gitlabBaseURL))
	if err != nil {
		log.Fatalf("Failed to create gitlab client: %v", err)
	}

	o := GitLabReleaseOptions{
		PackageConfigs: packageConfigs,
		gitlabClient:   client,
		Logger:         log.New(log.Writer(), "wolfictl check update: ", log.LstdFlags|log.Lmsgprefix),
		ErrorMessages:  make(map[string]string),
	}

	return o
}

func (o GitLabReleaseOptions) getLatestGitLabVersions() (map[string]NewVersionResults, map[string]string, error) {
	if len(o.PackageConfigs) == 0 {
		return nil, o.ErrorMessages, errors.New("No package configs provided")
	}

	releaseRepoList, tagRepoList := o.getSeparateRepoLists()

	latestVersionResults := make(map[string]NewVersionResults)

	if len(releaseRepoList) > 0 {
		o.Logger.Println("Checking for latest new releases")
		for packageName, identifier := range releaseRepoList {
			o.Logger.Printf("Checking for latest release on %s using identifier %s\n", packageName, identifier)
			listReleaseOption := &gitlab.ListReleasesOptions{
				ListOptions: gitlab.ListOptions{
					PerPage: 20,
					Page:    1,
				},
			}
			releases, resp, err := o.gitlabClient.Releases.ListReleases(identifier, listReleaseOption)
			if err != nil || resp.StatusCode != 200 {
				o.ErrorMessages[packageName] = fmt.Sprintf("Failed to list releases for %s: %v", packageName, err)
				continue
			}
			if len(releases) == 0 {
				o.ErrorMessages[packageName] = fmt.Sprintf("No releases found for %s", packageName)
				continue
			}

			// filter out releases that match the ignore regex patterns and other filters
			allReleaseList := []VersionComit{}
			for _, release := range releases {
				allReleaseList = append(allReleaseList, VersionComit{
					Version: release.TagName,
					Commit:  release.Commit.ID,
				})
			}
			properVersionList, err := prepareVersion(allReleaseList, &o.PackageConfigs[packageName].Config)
			if err != nil {
				o.ErrorMessages[packageName] = fmt.Sprintf("Failed to prepare version for %s: %v", packageName, err)
				continue
			}
			if len(properVersionList) > 0 {
				latestVersionResults[packageName] = NewVersionResults{
					Version: properVersionList[0].Version,
					Commit:  properVersionList[0].Commit,
				}
			}
		}
	}

	if len(tagRepoList) > 0 {
		o.Logger.Println("Checking for latest new tags")
		listTagsOption := &gitlab.ListTagsOptions{
			ListOptions: gitlab.ListOptions{
				PerPage: 50,
				Page:    1,
				OrderBy: "version",
			},
		}
		for packageName, identifier := range tagRepoList {
			o.Logger.Printf("Checking for latest tag on %s using projectID %s\n", packageName, identifier)
			tags, resp, err := o.gitlabClient.Tags.ListTags(identifier, listTagsOption)
			if err != nil || resp.StatusCode != 200 {
				o.ErrorMessages[packageName] = fmt.Sprintf("Failed to list tags for %s: %v", packageName, err)
				continue
			}
			if len(tags) == 0 {
				o.ErrorMessages[packageName] = fmt.Sprintf("No tags found for %s", packageName)
				continue
			}

			// filter out releases that match the ignore regex patterns and other filters
			allTagsList := []VersionComit{}
			for _, tag := range tags {
				allTagsList = append(allTagsList, VersionComit{
					Version: tag.Name,
					Commit:  tag.Commit.ID,
				})
			}
			properVersionList, err := prepareVersion(allTagsList, &o.PackageConfigs[packageName].Config)
			if err != nil {
				o.ErrorMessages[packageName] = fmt.Sprintf("Failed to prepare version for %s: %v", packageName, err)
				continue
			}
			if len(properVersionList) > 0 {
				latestVersionResults[packageName] = NewVersionResults{
					Version: properVersionList[0].Version,
					Commit:  properVersionList[0].Commit,
				}
			}
		}
	}

	return latestVersionResults, o.ErrorMessages, nil
}

func prepareVersion(versionList []VersionComit, packageConfig *config.Configuration) ([]VersionComit, error) {
	properVersionList := []VersionComit{}
	if len(versionList) == 0 {
		return properVersionList, errors.New("No versions found, empty list")
	}

	glm := packageConfig.Update.GitLabMonitor
	if glm == nil {
		return properVersionList, errors.New("No GitLab update configuration found for package")
	}

	for _, vc := range versionList {
		if len(packageConfig.Update.IgnoreRegexPatterns) > 0 {
			for _, pattern := range packageConfig.Update.IgnoreRegexPatterns {
				regex, err := regexp.Compile(pattern)
				if err != nil {
					return properVersionList, fmt.Errorf("Failed to compile regex %s", pattern)
				}
				if regex.MatchString(vc.Version) {
					continue
				}
			}
		}
		if glm.TagFilterPrefix != "" {
			if !strings.HasPrefix(vc.Version, glm.TagFilterPrefix) {
				continue
			}
		}
		if glm.TagFilterContains != "" {
			if !strings.Contains(vc.Version, glm.TagFilterContains) {
				continue
			}
		}

		version := vc.Version
		if glm.StripPrefix != "" {
			version = strings.TrimPrefix(version, glm.StripPrefix)
		}
		if glm.StripSuffix != "" {
			version = strings.TrimSuffix(version, glm.StripSuffix)
		}
		properVersionList = append(properVersionList, VersionComit{
			Version: version,
			Commit:  vc.Commit,
		})
	}

	return properVersionList, nil
}
func (o GitLabReleaseOptions) getSeparateRepoLists() (releaseRepoList, tagRepoList map[string]string) {
	tagRepoList = make(map[string]string)
	releaseRepoList = make(map[string]string)
	for _, pc := range o.PackageConfigs {
		if monitor := pc.Config.Update.GitLabMonitor; monitor != nil {
			identifire := monitor.Identifier
			if monitor.UseTags {
				tagRepoList[pc.Config.Package.Name] = identifire
			} else {
				releaseRepoList[pc.Config.Package.Name] = identifire
			}
		}
	}

	return releaseRepoList, tagRepoList
}
