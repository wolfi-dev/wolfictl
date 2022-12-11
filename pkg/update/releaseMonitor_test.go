package update

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"

	"github.com/stretchr/testify/assert"
)

func TestReleaseMonitor_parseVersions(t *testing.T) {

	m := MonitorService{Logger: log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix)}

	tests := []struct {
		name                  string
		expectedLatestVersion string
	}{
		{name: "versions", expectedLatestVersion: "2.3.1"},
		{name: "icu_versions", expectedLatestVersion: "72-1"},
	}
	for _, tt := range tests {
		data, err := os.ReadFile(filepath.Join("testdata", tt.name+".json"))
		assert.NoError(t, err)

		t.Run(tt.name, func(t *testing.T) {
			got, err := m.parseVersions(data)
			assert.NoError(t, err)
			assert.Equalf(t, tt.expectedLatestVersion, got, "parseVersions(%v)", tt.name)
			assert.Equalf(t, tt.expectedLatestVersion, got, "parseVersions(%v)", tt.name)
		})
	}
}

func TestMonitorService_getGet(t *testing.T) {
	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)
	httpClient := oauth2.NewClient(context.Background(), src)
	client := githubv4.NewClient(httpClient)

	// Query details about a GitHub repository releases

	var q struct {
		Search `graphql:"search(first: $count, query: $searchQuery, type: REPOSITORY)"`
	}
	variables := map[string]interface{}{
		"searchQuery": githubv4.String(fmt.Sprintf(`repo:%s repo:%s`, githubv4.String("jenkinsci/jenkins"), githubv4.String("sigstore/cosign"))),
		"count":       githubv4.Int(100),
		"first":       githubv4.Int(5),
	}

	err := client.Query(context.Background(), &q, variables)
	assert.NoError(t, err)

	printJSON(q)

}
