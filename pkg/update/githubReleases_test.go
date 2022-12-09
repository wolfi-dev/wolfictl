package update

import (
	"encoding/json"
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
	assert.Equal(t, "2.381", latestVersions["jenkinsci/jenkins"])
	assert.Equal(t, "v1.13.1", latestVersions["sigstore/cosign"])
}

type ReleasesSearchResponse struct {
	Search `json:"Search"`
}
