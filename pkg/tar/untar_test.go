package tar

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUntar(t *testing.T) {
	dir := t.TempDir()

	apk, err := os.Open(filepath.Join("testdata", "hello-world-0.0.1-r0.apk"))
	assert.NoError(t, err)

	err = Untar(apk, dir)
	assert.NoError(t, err)

	extracted, err := os.ReadFile(filepath.Join(dir, "usr", "tester"))
	assert.NoError(t, err)

	assert.Equal(t, []byte("test\n"), extracted)
}
