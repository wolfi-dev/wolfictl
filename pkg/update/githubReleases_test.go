package update

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/hashicorp/go-version"

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

			m := NewGitHubReleaseOptions(parsedMapperData, packageConfigs, nil)

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

func TestGitHubReleases_GetRepoList(t *testing.T) {
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

	rs := o.getRepoList(testData)

	assert.Equal(t, 4, len(rs))
	assert.Equal(t, len(rs[0]), 100)
	assert.Equal(t, len(rs[3]), 50)
}

func TestGitHubReleases_SortVersions(t *testing.T) {
	baseVersions := []string{"1.2.3", "1.1.1", "2.3.4", "0.1.3"}

	tests := []struct {
		name                  string
		baseVersions          []string
		testVersions          []string
		expectedLatestVersion string
	}{
		{
			name:                  "simple",
			baseVersions:          baseVersions,
			testVersions:          []string{"4.0.1"},
			expectedLatestVersion: "4.0.1",
		},
		{
			name:                  "fork",
			baseVersions:          baseVersions,
			testVersions:          []string{"4.0.1ab2", "4.0.1ab3", "4.0.1ab1"},
			expectedLatestVersion: "4.0.1ab3",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var versions []*version.Version

			// add test versions to the list first
			for _, v := range test.testVersions {
				semver, err := version.NewVersion(v)
				assert.NoError(t, err)
				versions = append(versions, semver)
			}

			// next add base versions
			for _, v := range test.baseVersions {
				semver, err := version.NewVersion(v)
				assert.NoError(t, err)
				versions = append(versions, semver)
			}

			sort.Sort(VersionsByLatest(versions))

			assert.Equal(t, test.expectedLatestVersion, versions[len(versions)-1].Original())
		})
	}
}
