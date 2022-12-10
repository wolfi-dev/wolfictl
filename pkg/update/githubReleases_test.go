package update

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMonitorService_parseGitHubReleases(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "graphql_versions_resuslts.json"))
	assert.NoError(t, err)
	assert.NotEmpty(t, data)
	m := GitHubReleaseOptions{Logger: log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix)}

	rel := &ReleasesSearchResponse{}
	err = json.Unmarshal(data, rel)
	assert.NoError(t, err)
	assert.NotEmpty(t, rel)

	latestVersions, _, err := m.parseGitHubReleases(rel.Search)
	assert.NoError(t, err)
	assert.Equal(t, "2.380", latestVersions["jenkins"])
	assert.Equal(t, "v1.13.1", latestVersions["cosign"])
}

type ReleasesSearchResponse struct {
	Search `json:"Search"`
}

// todo convert to test http server
//func TestMonitorService_API(t *testing.T) {
//	ts := oauth2.StaticTokenSource(
//		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
//	)
//
//	o := GitHubReleaseOptions{
//		Logger:           log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix),
//		GitGraphQLClient: githubv4.NewClient(oauth2.NewClient(context.Background(), ts)),
//	}
//	testData := make(map[string]Row)
//	testData["cosign"] = Row{
//		Identifier:  "sigstore/cosign",
//		ServiceName: "GITHUB",
//	}
//	testData["jenkins"] = Row{
//		Identifier:  "jenkinsci/jenkins",
//		ServiceName: "GITHUB",
//	}
//	//
//	//_, _, err := o.getLatestGitHubVersions(testData)
//	//assert.NoError(t, err)
//	//DoIt()
//	//DoItAgain()
//	rs, errorMessages, err := o.DoItAgain2(testData)
//	assert.NoError(t, err)
//	assert.Empty(t, errorMessages)
//	assert.NotEmpty(t, rs)
//	assert.Equal(t, rs["jenkinsci/jenkins"], "2.381")
//	assert.Equal(t, rs["sigstore/cosign"], "v1.13.1")
//
//	//DoIt(testData)
//}

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
