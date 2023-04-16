package tar

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUntar(t *testing.T) {
	dir := t.TempDir()

	apk, err := os.Open(filepath.Join("testdata", "hello-wolfi-2.12-r1.apk"))
	assert.NoError(t, err)

	err = Untar(apk, dir)
	assert.NoError(t, err)

	extracted, err := os.ReadFile(filepath.Join(dir, "usr", "bin", "hello"))
	assert.NoError(t, err)
	assert.NotEmpty(t, extracted)
}
