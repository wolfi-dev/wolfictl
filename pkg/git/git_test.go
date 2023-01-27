package git

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseGitURL(t *testing.T) {
	tests := []struct {
		rawURL   string
		scheme   string
		org      string
		repoName string
	}{
		{
			rawURL:   "https://github.com/foo/bar",
			scheme:   "https",
			org:      "foo",
			repoName: "bar",
		},
		{
			rawURL:   "https://github.com/foo/bar.git",
			scheme:   "https",
			org:      "foo",
			repoName: "bar",
		},
		{
			rawURL:   "git@github.com:cheese/wine.git",
			scheme:   "git",
			org:      "cheese",
			repoName: "wine",
		},
	}
	for _, test := range tests {
		t.Run(test.rawURL, func(t *testing.T) {
			got, err := ParseGitURL(test.rawURL)
			assert.NoError(t, err)

			assert.Equal(t, test.scheme, got.Scheme)
			assert.Equal(t, test.org, got.Organisation)
			assert.Equal(t, test.repoName, got.Name)
		})
	}
}
