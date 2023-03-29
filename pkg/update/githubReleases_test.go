package update

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/go-version"

	"chainguard.dev/melange/pkg/build"

	"github.com/wolfi-dev/wolfictl/pkg/melange"

	"github.com/stretchr/testify/assert"
)

func TestMonitorService_parseGitHubReleases(t *testing.T) {
	packageConfigs := make(map[string]melange.Packages)

	packageConfigs["cosign"] = melange.Packages{
		Config: build.Configuration{
			Package: build.Package{Name: "cosign", Version: "1.10.1"},
			Update: build.Update{GitHubMonitor: &build.GitHubMonitor{
				Identifier:  "sigstore/cosign",
				StripPrefix: "v",
			}},
		},
	}

	packageConfigs["jenkins"] = melange.Packages{
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
			expectedVersion: "1.13.1",
		},
		{
			name:            "multiple_repos",
			packageName:     "jenkins",
			expectedVersion: "2.388",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", test.name, "graphql_versions_results.json"))
			assert.NoError(t, err)
			assert.NotEmpty(t, data)

			m := NewGitHubReleaseOptions(packageConfigs, nil, nil)

			var rel []Repository
			err = json.Unmarshal(data, &rel)
			assert.NoError(t, err)
			assert.NotEmpty(t, rel)

			errorMessages := make(map[string]string)

			latestVersions, err := m.parseGitHubReleases(rel, errorMessages)
			assert.NoError(t, err)
			assert.Empty(t, errorMessages)
			assert.Equal(t, test.expectedVersion, latestVersions[test.packageName])
		})
	}
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

			packageConfigs := make(map[string]melange.Packages)

			packageConfigs[test.packageName] = melange.Packages{
				Config: test.updateConfig,
			}

			m := NewGitHubReleaseOptions(packageConfigs, nil, nil)

			var rel QueryTagsResponse
			err = json.Unmarshal(data, &rel)
			assert.NoError(t, err)
			assert.NotEmpty(t, rel)

			errorMessages := make(map[string]string)
			latestVersions, _ := m.parseGitHubTags(rel, errorMessages)
			assert.Equal(t, test.expectedVersion, latestVersions[test.packageName])
			assert.Empty(t, errorMessages)
		})
	}
}

func TestGitHubReleases_GetRepoListsTags(t *testing.T) {
	testData := make(map[string]melange.Packages)

	for i := 0; i < 350; i++ {
		item := fmt.Sprintf("cheese%d", i)

		testData[item] = melange.Packages{Config: build.Configuration{
			Package: build.Package{
				Name: item,
			},
			Update: build.Update{
				GitHubMonitor: &build.GitHubMonitor{
					Identifier: "wine/" + item,
					UseTags:    true,
				},
			},
		}}
	}

	o := GitHubReleaseOptions{
		Logger:         log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix),
		PackageConfigs: testData,
	}

	rs1, rs2 := o.getRepoLists()

	assert.Equal(t, 4, len(rs2))
	assert.Equal(t, 0, len(rs1))
	assert.Equal(t, len(rs2[0]), 100)
	assert.Equal(t, len(rs2[3]), 50)
}

func TestGitHubReleases_GetRepoListsReleases(t *testing.T) {
	testData := make(map[string]melange.Packages)

	for i := 0; i < 350; i++ {
		item := fmt.Sprintf("cheese%d", i)

		testData[item] = melange.Packages{Config: build.Configuration{
			Package: build.Package{
				Name: item,
			},
			Update: build.Update{
				GitHubMonitor: &build.GitHubMonitor{
					Identifier: "wine/" + item,
				},
			},
		}}
	}

	o := GitHubReleaseOptions{
		Logger:         log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix),
		PackageConfigs: testData,
	}

	rs1, rs2 := o.getRepoLists()

	assert.Equal(t, 4, len(rs1))
	assert.Equal(t, 0, len(rs2))
	assert.Equal(t, len(rs1[0]), 100)
	assert.Equal(t, len(rs1[3]), 50)
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

			v, err := version.NewVersion(tt.version)
			assert.NoError(t, err)

			assert.Equalf(t, tt.skip, o.isVersionPreRelease(v, "cheese/crackers"), "isVersionPreRelease(%v)", v)
		})
	}
}

func TestGitHubRelease_getBatches(t *testing.T) {
	tests := []struct {
		packageName    string
		identifier     string
		numberToCreate int
		batchCount     int
	}{
		{packageName: "foo", identifier: "cheese/wine", numberToCreate: 250, batchCount: 3},
		{packageName: "foo", identifier: "cheese/wine", numberToCreate: 5, batchCount: 1},
	}
	for _, tt := range tests {
		t.Run(tt.packageName, func(t *testing.T) {

			repos := make(map[string]string)
			for i := 0; i < tt.numberToCreate; i++ {
				repos[fmt.Sprintf("%s-%d", tt.packageName, i)] = tt.identifier
			}

			got := getBatches(repos)
			assert.Len(t, got, tt.batchCount)
		})
	}
}
