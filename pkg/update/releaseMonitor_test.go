package update

import (
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMonitorService_parseData(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "release_mapper_data.txt"))
	assert.NoError(t, err)

	m := MonitorService{Logger: log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix)}
	mapperData, err := m.parseData(string(data))
	assert.NoError(t, err)
	assert.Equal(t, "16", mapperData["acl"].Identifier)
	assert.Equal(t, "7981", mapperData["binutils"].Identifier)
	assert.Equal(t, "", mapperData["bazel-5"].Identifier)
}

func TestMonitorService_parseVersions(t *testing.T) {

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
