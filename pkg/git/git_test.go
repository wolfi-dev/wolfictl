package git

import (
	"os"
	"testing"

	gitHttp "github.com/go-git/go-git/v5/plumbing/transport/http"

	"github.com/stretchr/testify/assert"
)

func TestParseGitURL(t *testing.T) {
	tests := []struct {
		rawURL    string
		scheme    string
		org       string
		repoName  string
		errorText string
	}{
		{
			rawURL:    "https://github.com/foo/bar",
			scheme:    "https",
			org:       "foo",
			repoName:  "bar",
			errorText: "",
		},
		{
			rawURL:    "https://github.com/foo/bar.git",
			scheme:    "https",
			org:       "foo",
			repoName:  "bar",
			errorText: "",
		},
		{
			rawURL:    "git@github.com:cheese/wine.git",
			scheme:    "git",
			org:       "cheese",
			repoName:  "wine",
			errorText: "",
		},
		{
			rawURL:    "https://example.com/",
			scheme:    "https",
			org:       "",
			repoName:  "",
			errorText: "",
		},
		{
			rawURL:    "http://example.com/",
			scheme:    "http",
			org:       "",
			repoName:  "",
			errorText: "unsupported scheme: http",
		},
	}
	for _, test := range tests {
		t.Run(test.rawURL, func(t *testing.T) {
			got, err := ParseGitURL(test.rawURL)
			if test.errorText == "" {
				assert.NoError(t, err)
			} else {
				assert.Equal(t, test.errorText, err.Error())
				return
			}

			assert.Equal(t, test.scheme, got.Scheme)
			assert.Equal(t, test.org, got.Organisation)
			assert.Equal(t, test.repoName, got.Name)
		})
	}
}

func TestGetGitAuth(t *testing.T) {
	tests := []struct {
		name           string
		gitURL         string
		envToken       string
		expectedError  bool
		expectedAuth   *gitHttp.BasicAuth
		expectedErrMsg string
	}{
		{
			name:           "Empty URL",
			gitURL:         "",
			envToken:       "",
			expectedError:  true,
			expectedAuth:   nil,
			expectedErrMsg: "failed to parse git URL \"\": ",
		},
		{
			name:           "Malformed URL",
			gitURL:         "://invalid-url",
			envToken:       "",
			expectedError:  true,
			expectedAuth:   nil,
			expectedErrMsg: "failed to parse git URL \"://invalid-url\": ",
		},
		{
			name:           "Non-GitHub Host",
			gitURL:         "https://example.com/cheese/repo.git",
			envToken:       "",
			expectedError:  false,
			expectedAuth:   nil,
			expectedErrMsg: "",
		},
		{
			name:           "GitHub Host with No Token",
			gitURL:         "https://github.com/cheese/repo.git",
			envToken:       "",
			expectedError:  false,
			expectedAuth:   &gitHttp.BasicAuth{},
			expectedErrMsg: "",
		},
		{
			name:           "GitHub Host with Token",
			gitURL:         "https://github.com/cheese/repo.git",
			envToken:       "test-token",
			expectedError:  false,
			expectedAuth:   &gitHttp.BasicAuth{Username: "abc123", Password: "test-token"},
			expectedErrMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envToken != "" {
				os.Setenv("GITHUB_TOKEN", tt.envToken)
				defer os.Unsetenv("GITHUB_TOKEN")
			}

			auth, err := GetGitAuth(tt.gitURL)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedAuth, auth)
			}
		})
	}
}
