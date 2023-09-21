package gh

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-github/v55/github"
	"github.com/stretchr/testify/assert"
)

func TestCheckExistingIssue(t *testing.T) {
	// Create a test server that simulates the GitHub API
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Respond with a JSON array of issues
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`[
			{
				"number": 1,
				"title": "wolfi-bot/foo-package"
			},
			{
				"number": 2,
				"title": "wolfi-bot/bar-package"
			}
		]`))
		assert.NoError(t, err)
	}))
	defer testServer.Close()

	// Create a mock GitHub client
	httpClient := testServer.Client()
	baseURL := testServer.URL
	client := github.NewClient(httpClient)
	var err error
	client.BaseURL, err = url.Parse(baseURL + "/")
	assert.NoError(t, err)

	// Initialize the GitOptions struct
	gitOptions := GitOptions{
		GithubClient: client,
		MaxRetries:   3,
	}

	// Test the CheckExistingIssue function
	ctx := context.Background()
	issues := &Issues{
		Owner:       "cheese",
		RepoName:    "crisps",
		PackageName: "foo-package",
		Title:       GetErrorIssueTitle("wolfi-bot", "foo-package"),
	}
	issueNumber, err := gitOptions.CheckExistingIssue(ctx, issues)

	// Assert that the issue number is correct and there's no error
	assert.NoError(t, err)
	assert.Equal(t, 1, issueNumber)
}

func TestOpenIssue(t *testing.T) {
	// Create a test server that simulates the GitHub API
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Respond with the created issue JSON
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, err := w.Write([]byte(`{
			"number": 1,
			"title": "wolfi-bot/foo-package",
			"html_url": "https://github.com/cheese/crisps/issues/1"
		}`))
		assert.NoError(t, err)
	}))
	defer testServer.Close()

	// Create a mock GitHub client
	httpClient := testServer.Client()
	baseURL := testServer.URL
	client := github.NewClient(httpClient)
	var err error
	client.BaseURL, err = url.Parse(baseURL + "/")
	assert.NoError(t, err)

	// Initialize the GitOptions struct
	gitOptions := GitOptions{
		GithubClient: client,
		MaxRetries:   3,
	}

	// Test the OpenIssue function
	ctx := context.Background()
	issues := &Issues{
		Owner:       "cheese",
		RepoName:    "crisps",
		PackageName: "foo-package",
		Comment:     "This is a test issue",
		Title:       GetErrorIssueTitle("wolfi-bot", "foo-package"),
		Labels:      []string{"prawn", "cocktail"},
	}
	htmlURL, err := gitOptions.OpenIssue(ctx, issues)

	// Assert that the returned HTML URL is correct and there's no error
	assert.NoError(t, err)
	assert.Equal(t, "https://github.com/cheese/crisps/issues/1", htmlURL)
}

func TestGitOptions_CloseIssue(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"number":1,"state":"closed","body":"test comment"}`)
	}))
	defer testServer.Close()

	httpClient := testServer.Client()
	ctx := context.Background()

	baseURL := testServer.URL
	client := github.NewClient(httpClient)
	var err error
	client.BaseURL, err = url.Parse(baseURL + "/")
	assert.NoError(t, err)

	gitOptions := GitOptions{
		GithubClient: client,
	}

	err = gitOptions.CloseIssue(ctx, "testOrg", "testRepo", "test comment", 1)
	assert.NoError(t, err)
}
