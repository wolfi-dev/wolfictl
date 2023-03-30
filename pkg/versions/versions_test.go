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
			name:                  "underscore",
			baseVersions:          baseVersions,
			testVersions:          []string{"5.2_rc4"},
			expectedLatestVersion: "5.2rc4",
		},
		{
			name:                  "fork",
			baseVersions:          baseVersions,
			testVersions:          []string{"4.0.1ab2", "4.0.1ab3", "4.0.1ab1"},
			expectedLatestVersion: "4.0.1ab3",
		},
		{
			name:                  "prerelease",
			baseVersions:          baseVersions,
			testVersions:          []string{"4.0.1-ab2", "4.0.1-ab3", "4.0.1-ab1"},
			expectedLatestVersion: "4.0.1-ab3",
		},
		{
			name:                  "metadata",
			testVersions:          []string{"1.2.3+1", "1.2.3+2", "1.2.3+3", "1.2.3+4", "1.2.3+5", "1.2.3"},
			expectedLatestVersion: "1.2.3+5",
		},
		{
			name:                  "jdk",
			testVersions:          []string{"17+32", "17+33", "17.0.7+5"},
			expectedLatestVersion: "17.0.7+5",
		},
		{
			name:                  "zookeeper",
			testVersions:          []string{"3.8.1", "3.8.1-1"},
			expectedLatestVersion: "3.8.1",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var versions []*version.Version

			// add test versions to the list first
			for _, v := range test.testVersions {
				semver, err := NewVersion(v)
				assert.NoError(t, err)
				versions = append(versions, semver)
			}

			// next add base versions
			for _, v := range test.baseVersions {
				semver, err := NewVersion(v)
				assert.NoError(t, err)
				versions = append(versions, semver)
			}

			sort.Sort(ByLatest(versions))

			assert.Equal(t, test.expectedLatestVersion, versions[len(versions)-1].Original())
		})
	}
}
