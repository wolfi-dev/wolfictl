package versions

import (
	"sort"
	"strings"
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

func TestSort_ByLatestStrings(t *testing.T) {
	cases := []struct {
		input    []string
		expected []string
	}{
		{
			input:    []string{"1.2.3", "1.1.1", "2.3.4", "0.1.3"},
			expected: []string{"2.3.4", "1.2.3", "1.1.1", "0.1.3"},
		},
		{
			input:    []string{"0.1.0-r5", "0.1.0-r4", "0.2.0-r0"},
			expected: []string{"0.2.0-r0", "0.1.0-r5", "0.1.0-r4"},
		},
		{
			input:    []string{"0.1.0-r5", "0.1.0-r1", "0.1.0-r12"},
			expected: []string{"0.1.0-r12", "0.1.0-r5", "0.1.0-r1"},
		},
		{
			input:    []string{"0.1.0-r15", "0.1.0-r1", "0.1.0-r12"},
			expected: []string{"0.1.0-r15", "0.1.0-r12", "0.1.0-r1"},
		},
		{
			input:    []string{"1.1.0-r3", "0.1.0-r1", "0.1.0-r12"},
			expected: []string{"1.1.0-r3", "0.1.0-r12", "0.1.0-r1"},
		},
		{
			input:    []string{"2.1.0-r1", "2.1.0-r2", "0.1.0-r12"},
			expected: []string{"2.1.0-r2", "2.1.0-r1", "0.1.0-r12"},
		},
		{
			input:    []string{"5.0.0-r1", "9.1.0-r22", "9.1.0-r20"},
			expected: []string{"9.1.0-r22", "9.1.0-r20", "5.0.0-r1"},
		},
	}

	for _, tt := range cases {
		t.Run(strings.Join(tt.input, ","), func(t *testing.T) {
			sort.Sort(ByLatestStrings(tt.input))
			assert.Equal(t, tt.expected, tt.input)
		})
	}
}
