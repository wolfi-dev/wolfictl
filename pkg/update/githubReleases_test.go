package update

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"chainguard.dev/melange/pkg/build"

	"github.com/wolfi-dev/wolfictl/pkg/melange"

	"github.com/stretchr/testify/assert"
)

func TestMonitorService_parseGitHubReleases(t *testing.T) {
	packageConfigs := make(map[string]*melange.Packages)

	packageConfigs["cosign"] = &melange.Packages{
		Config: build.Configuration{
			Package: build.Package{Name: "cosign", Version: "1.10.1"},
			Update: build.Update{GitHubMonitor: &build.GitHubMonitor{
				Identifier:  "sigstore/cosign",
				StripPrefix: "v",
			}},
		},
	}

	packageConfigs["jenkins"] = &melange.Packages{
		Config: build.Configuration{
			Package: build.Package{Name: "jenkins", Version: "2.370"},
			Update: build.Update{GitHubMonitor: &build.GitHubMonitor{
				Identifier:  "jenkinsci/jenkins",
				StripPrefix: "jenkins-",
			}},
		},
	}
	tests := []struct {
		name            string
		packageName     string
		initialVersion  string
		expectedVersion string
		githubMonitor   build.GitHubMonitor
	}{
		{
			name:            "multiple_repos",
			packageName:     "cosign",
			expectedVersion: "2.0.0",
		},
		{
			name:            "multiple_repos",
			packageName:     "jenkins",
			expectedVersion: "2.397",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", test.name, "graphql_versions_results.json"))
			assert.NoError(t, err)
			assert.NotEmpty(t, data)

			m := NewGitHubReleaseOptions(packageConfigs, nil)

			rel := QueryReleasesResponse{}
			err = json.Unmarshal(data, &rel)
			assert.NoError(t, err)
			assert.NotEmpty(t, rel)

			rel.Data = getReleaseResultsMapWithHashKeys(rel, m)

			errorMessages := make(map[string]string)

			latestVersions, err := m.parseGitHubReleases(&rel)
			assert.NoError(t, err)
			assert.Empty(t, errorMessages)
			assert.Equal(t, test.expectedVersion, latestVersions[test.packageName].Version)
		})
	}
}

func getReleaseResultsMapWithHashKeys(rel QueryReleasesResponse, m GitHubReleaseOptions) map[string]Releases {
	// modify the fake github response with the hash keys generated from NewGitHubReleaseOptions
	// this is so we can match the response back with the melange package
	copyMap := make(map[string]Releases)
	for old, config := range rel.Data {
		for s, packages := range m.PackageConfigs {
			if packages.Config.Update.GitHubMonitor.Identifier == config.NameWithOwner {
				copyMap[m.PackageConfigs[s].Hash] = config
				delete(rel.Data, old)
				continue
			}
		}
	}
	return copyMap
}
func getTagResultsMapWithHashKeys(rel QueryTagsResponse, m GitHubReleaseOptions) map[string]Repo {
	// modify the fake github response with the hash keys generated from NewGitHubReleaseOptions
	// this is so we can match the response back with the melange package
	copyMap := make(map[string]Repo)
	for old, config := range rel.Data {
		for s, packages := range m.PackageConfigs {
			if packages.Config.Update.GitHubMonitor.Identifier == config.NameWithOwner {
				copyMap[m.PackageConfigs[s].Hash] = config
				delete(rel.Data, old)
				continue
			}
		}
	}
	return copyMap
}

func TestMonitorService_parseGitHubTags(t *testing.T) {
	tests := []struct {
		name            string
		packageName     string
		expectedVersion string
		updateConfig    build.Configuration
	}{
		{
			name:            "parse_go_tags",
			packageName:     "go-1.19",
			expectedVersion: "1.19.7",
			updateConfig: build.Configuration{
				Package: build.Package{Name: "go-1.19", Version: "1.19.1"},
				Update: build.Update{
					Enabled: true,
					GitHubMonitor: &build.GitHubMonitor{
						Identifier:  "golang/go",
						TagFilter:   "go1.19",
						StripPrefix: "go",
					},
				},
			},
		},
		{
			name:            "parse_java_tags",
			packageName:     "openjdk-11",
			expectedVersion: "11.0.19+5",
			updateConfig: build.Configuration{
				Package: build.Package{Name: "openjdk-11", Version: "11.0.16"},
				Update: build.Update{
					Enabled: true,
					GitHubMonitor: &build.GitHubMonitor{
						Identifier:  "openjdk/jdk11u",
						TagFilter:   "jdk-17",
						StripPrefix: "jdk-",
					},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", test.name, "graphql_versions_results.json"))
			assert.NoError(t, err)
			assert.NotEmpty(t, data)

			packageConfigs := make(map[string]*melange.Packages)

			packageConfigs[test.packageName] = &melange.Packages{
				Config: test.updateConfig,
			}

			m := NewGitHubReleaseOptions(packageConfigs, nil)

			var rel QueryTagsResponse
			err = json.Unmarshal(data, &rel)
			assert.NoError(t, err)
			assert.NotEmpty(t, rel)

			rel.Data = getTagResultsMapWithHashKeys(rel, m)

			errorMessages := make(map[string]string)
			latestVersions, err := m.parseGitHubTags(&rel)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedVersion, latestVersions[test.packageName].Version)
			assert.Empty(t, errorMessages)
		})
	}
}

func Test_queryTemplate(t *testing.T) {
	data := QueryTagsData{
		RepoList: []RepoQuery{
			{Owner: "golang", Name: "go", Filter: "go1.19"},
			{Owner: "openjdk", Name: "jdk11u", Filter: "jdk-11"},
		},
	}

	got := template(queryTags, data)
	assert.NotEmpty(t, got)

	expected, err := os.ReadFile(filepath.Join("testdata", "query_tags", "result"))
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	assert.Equal(t, strings.TrimSpace(string(expected)), strings.TrimSpace(got))
}

func Test_queryTagsResult(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "git_tags", "graphql_versions_results.json"))
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	var response QueryTagsResponse
	err = json.Unmarshal(data, &response)
	assert.NoError(t, err)

	assert.Equal(t, 2, len(response.Data))
	assert.Contains(t, "golang/go", response.Data["repo_0"].NameWithOwner)
	assert.Contains(t, "openjdk/jdk11u", response.Data["repo_1"].NameWithOwner)
}

func TestGitHubReleaseOptions_isVersionPreRelease(t *testing.T) {
	tests := []struct {
		version string
		skip    bool
	}{
		{version: "1.2.3-alpha", skip: true},
		{version: "1.2.3-beta", skip: true},
		{version: "1.2.3-rc", skip: true},
		{version: "1.2.3", skip: false},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			o := GitHubReleaseOptions{
				Logger: log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix),
			}

			assert.Equalf(t, tt.skip, o.shouldSkipVersion(tt.version), "isVersionPreRelease(%v)", tt.version)
		})
	}
}

func Test_getCommit(t *testing.T) {
	tests := []struct {
		name         string
		commitURLStr string
		want         string
		wantErr      assert.ErrorAssertionFunc
	}{
		{name: "simple", commitURLStr: "https://github.com/golang/go/commit/7bd22aafe41be40e2174335a3dc55431ca9548ec", want: "7bd22aafe41be40e2174335a3dc55431ca9548ec", wantErr: assert.NoError},
		{name: "bad_sha", commitURLStr: "https://github.com/golang/go/commit/abc123", want: "", wantErr: assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getCommit(tt.commitURLStr)
			if !tt.wantErr(t, err, fmt.Sprintf("getCommit(%v)", tt.commitURLStr)) {
				return
			}
			assert.Equalf(t, tt.want, got, "getCommit(%v)", tt.commitURLStr)
		})
	}
}
