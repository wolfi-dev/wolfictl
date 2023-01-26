package update

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
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
