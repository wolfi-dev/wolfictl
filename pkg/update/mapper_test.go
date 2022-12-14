package update

import (
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapper_parseData(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "release_mapper_data.txt"))
	assert.NoError(t, err)

	o := Options{Logger: log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix)}
	mapperData, err := o.parseData(string(data))
	assert.NoError(t, err)
	assert.Equal(t, "16", mapperData["acl"].Identifier)
	assert.Equal(t, "7981", mapperData["binutils"].Identifier)
	assert.Equal(t, "", mapperData["bazel-5"].Identifier)
	assert.Equal(t, "sigstore/cosign", mapperData["cosign"].Identifier)
	assert.Equal(t, "GITHUB", mapperData["cosign"].ServiceName)
}
