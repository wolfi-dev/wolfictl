package melange

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// make sure apko yaml files are skipped and no errors
func TestMelange_readPackageConfigsNotSubFolders(t *testing.T) {
	packages, err := ReadPackageConfigs([]string{}, filepath.Join("testdata", "melange_dir"))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(packages))
}
