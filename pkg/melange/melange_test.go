package melange

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// make sure apko yaml files are skipped and no errors
func TestMelange_readPackageConfigsNotSubFolders(t *testing.T) {
	ctx := context.Background()
	packages, err := ReadPackageConfigs(ctx, []string{}, filepath.Join("testdata", "melange_dir"))
	assert.NoError(t, err)
	assert.Equal(t, 4, len(packages))
}

func TestMelange_readPackageConfigForFoo(t *testing.T) {
	ctx := context.Background()
	packages, err := ReadPackageConfigs(ctx, []string{"foo"}, filepath.Join("testdata", "melange_dir"))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(packages))
}

func TestMelange_readAllPackages(t *testing.T) {
	ctx := context.Background()
	packages, err := ReadAllPackagesFromRepo(ctx, filepath.Join("testdata", "melange_dir"))
	assert.NoError(t, err)
	assert.Equal(t, 4, len(packages))
}

func TestMelange_readPackageConfigForBar(t *testing.T) {
	ctx := context.Background()
	packages, err := ReadPackageConfigs(ctx, []string{"bar"}, filepath.Join("testdata", "melange_dir"))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(packages))
}

func TestMelange_readPackageConfigForArgocdVersionStream(t *testing.T) {
	ctx := context.Background()
	packages, err := ReadPackageConfigs(ctx, []string{"argo-cd-2.9", "argo-cd-2.10"}, filepath.Join("testdata", "melange_dir"))
	assert.NoError(t, err)
	assert.Equal(t, 2, len(packages))
}
