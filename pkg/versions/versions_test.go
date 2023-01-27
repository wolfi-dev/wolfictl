package versions

import (
	"sort"
	"testing"

	"github.com/hashicorp/go-version"
	"github.com/stretchr/testify/assert"
)

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
		{
			name:                  "large",
			testVersions:          []string{"v1.2.3", "v1.2.3ab1", "v1.2.3ab2", "v1.2.4ab1", "v1.2.4ab10", "v1.2.4ab2", "v1.2.4ab3", "v1.2.4ab4", "v1.2.4ab5", "v1.2.4ab6", "v1.2.4ab7", "v1.2.4ab8", "v1.2.4ab9"},
			expectedLatestVersion: "v1.2.4ab10",
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

			sort.Sort(ByLatest(versions))

			assert.Equal(t, test.expectedLatestVersion, versions[len(versions)-1].Original())
		})
	}
}
