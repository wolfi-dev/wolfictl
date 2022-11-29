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
	data, err := os.ReadFile(filepath.Join("testdata", "versions.json"))
	assert.NoError(t, err)

	m := MonitorService{Logger: log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix)}
	version, err := m.parseVersions(data)

	assert.NoError(t, err)
	assert.Equal(t, "2.3.1", version)
}
