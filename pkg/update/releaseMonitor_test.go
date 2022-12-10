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

//
//func TestMonitorService_getLatestGitHubVersions(t *testing.T) {
//
//	ts := oauth2.StaticTokenSource(
//		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
//	)
//	client := oauth2.NewClient(context.Background(), ts)
//	transport := Interceptor{http.DefaultTransport}
//
//	client.Transport = transport
//
//	m := MonitorService{Logger: log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix)}
//
//	m.GitGraphQLClient = githubv4.NewClient(client)
//
//	testData := make(map[string]Row)
//
//	testData["jenkins"] = Row{
//		Identifier:  "jenkinsci/jenkins",
//		ServiceName: "GITHUB",
//	}
//	packagesToUpdate, _, err := m.getLatestGitHubVersions(testData)
//	assert.NoError(t, err)
//	for k, v := range packagesToUpdate {
//		t.Logf("%s %v", k, v)
//	}
//}

//type Interceptor struct {
//	core http.RoundTripper
//}

//func (i Interceptor) RoundTrip(r *http.Request) (*http.Response, error) {
//	defer func() {
//		_ = r.Body.Close()
//	}()
//
//	b, err := io.ReadAll(r.Body)
//	if err != nil {
//		log.Fatalln(err)
//	}
//
//	fmt.Println(string(b))
//
//	return i.core.RoundTrip(r)
//}

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
	fmt.Println("searchQuery:", variables["searchQuery"])
	err := client.Query(context.Background(), &q, variables)
	assert.NoError(t, err)

	printJSON(q)

}

//func TestMonitorService_getGet(t *testing.T) {
//	src := oauth2.StaticTokenSource(
//		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
//	)
//	httpClient := oauth2.NewClient(context.Background(), src)
//	client := githubv4.NewClient(httpClient)
//
//	// Query details about a GitHub repository releases
//	{
//		var q struct {
//			Search struct {
//				RepositoryCount githubv4.Int
//				Edges           []struct {
//					Node struct {
//						Repository struct {
//							Releases struct {
//								TotalCount  githubv4.Int
//								ReleaseEdge []struct {
//									Release struct {
//										Name         githubv4.String
//										IsPrerelease githubv4.Boolean
//										IsDraft      githubv4.Boolean
//										IsLatest     githubv4.Boolean
//									} `graphql:"node"`
//								} `graphql:"edges"`
//							} `graphql:"releases(first: $first)"`
//							NameWithOwner githubv4.String
//						} `graphql:"... on Repository"`
//					}
//				}
//			} `graphql:"search(first: $count, query: $searchQuery, type: REPOSITORY)"`
//		}
//		variables := map[string]interface{}{
//			"searchQuery": githubv4.String(fmt.Sprintf(`repo:%s repo:%s`, githubv4.String("jenkinsci/jenkins"), githubv4.String("sigstore/cosign"))),
//			"count":       githubv4.Int(100),
//			"first":       githubv4.Int(5),
//		}
//		fmt.Println("searchQuery:", variables["searchQuery"])
//		err := client.Query(context.Background(), &q, variables)
//		assert.NoError(t, err)
//
//		printJSON(q)
//	}
//
//}
