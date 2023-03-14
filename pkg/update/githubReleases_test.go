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
	tests := []struct {
		name            string
		packageName     string
		initialVersion  string
		expectedVersion string
	}{
		{
			name:            "multiple_repos",
			packageName:     "cosign",
			initialVersion:  "1.10.1",
			expectedVersion: "1.13.1",
		},
		{
			name:            "multiple_repos",
			packageName:     "jenkins",
			initialVersion:  "2.370",
			expectedVersion: "2.388",
		},
		{
			name:            "complex_versions",
			packageName:     "cheese",
			initialVersion:  "1.2.3",
			expectedVersion: "1.2.4-cg2",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", test.name, "graphql_versions_results.json"))
			assert.NoError(t, err)
			assert.NotEmpty(t, data)

			mapperData, err := os.ReadFile(filepath.Join("testdata", test.name, "release_mapper_data.txt"))
			assert.NoError(t, err)

			o := Options{Logger: log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix)}
			parsedMapperData, err := o.parseData(string(mapperData))
			assert.NoError(t, err)

			packageConfigs := make(map[string]melange.Packages)

			packageConfigs[test.packageName] = melange.Packages{
				Config: build.Configuration{
					Package: build.Package{Name: test.packageName, Version: test.initialVersion},
				},
			}

			m := NewGitHubReleaseOptions(parsedMapperData, packageConfigs, nil, nil)

			var rel []Repository
			err = json.Unmarshal(data, &rel)
			assert.NoError(t, err)
			assert.NotEmpty(t, rel)

			latestVersions, _, err := m.parseGitHubReleases(rel)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedVersion, latestVersions[test.packageName])
		})
	}
}

func TestMonitorService_parseGitHubTags(t *testing.T) {
	tests := []struct {
		name            string
		packageName     string
		initialVersion  string
		expectedVersion string
	}{
		{
			name:            "parse_go_tags",
			packageName:     "go-1.19",
			initialVersion:  "1.19.1",
			expectedVersion: "1.19.7",
		},
		{
			name:            "parse_java_tags",
			packageName:     "openjdk-11",
			initialVersion:  "11.0.16",
			expectedVersion: "11.0.19+5",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", test.name, "graphql_versions_results.json"))
			assert.NoError(t, err)
			assert.NotEmpty(t, data)

			mapperData, err := os.ReadFile(filepath.Join("testdata", test.name, "release_mapper_data.txt"))
			assert.NoError(t, err)

			o := Options{Logger: log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix)}
			parsedMapperData, err := o.parseData(string(mapperData))
			assert.NoError(t, err)

			packageConfigs := make(map[string]melange.Packages)

			packageConfigs[test.packageName] = melange.Packages{
				Config: build.Configuration{
					Package: build.Package{Name: test.packageName, Version: test.initialVersion},
				},
			}

			m := NewGitHubReleaseOptions(parsedMapperData, packageConfigs, nil, nil)

			var rel QueryTagsResponse
			err = json.Unmarshal(data, &rel)
			assert.NoError(t, err)
			assert.NotEmpty(t, rel)

			latestVersions, _, err := m.parseGitHubTags(rel)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedVersion, latestVersions[test.packageName])
		})
	}
}

func TestGitHubReleases_GetRepoLists(t *testing.T) {
	testData := make(map[string]Row)

	for i := 0; i < 350; i++ {
		item := fmt.Sprintf("cheese%d", i)
		testData[item] = Row{
			Identifier:  "wine/" + item,
			ServiceName: "GITHUB",
		}
	}

	o := GitHubReleaseOptions{
		Logger: log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix),
	}

	rs1, rs2 := o.getRepoLists(testData)

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
