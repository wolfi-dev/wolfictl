package advisory

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/configs/build"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func TestValidate(t *testing.T) {
	t.Run("diff", func(t *testing.T) {
		cases := []struct {
			name          string
			shouldBeValid bool
		}{
			{
				name:          "same",
				shouldBeValid: true,
			},
			{
				name:          "added-document",
				shouldBeValid: true,
			},
			{
				name:          "removed-document",
				shouldBeValid: false,
			},
			{
				name:          "added-advisory",
				shouldBeValid: true,
			},
			{
				name:          "removed-advisory",
				shouldBeValid: false,
			},
			{
				name:          "added-event",
				shouldBeValid: true,
			},
			{
				name:          "removed-event",
				shouldBeValid: false,
			},
			{
				name:          "modified-advisory-outside-of-events",
				shouldBeValid: true,
			},
			{
				name:          "added-event-with-non-recent-timestamp",
				shouldBeValid: false,
			},
		}

		for _, tt := range cases {
			t.Run(tt.name, func(t *testing.T) {
				aDir := filepath.Join("testdata", "diff", tt.name, "a")
				bDir := filepath.Join("testdata", "diff", tt.name, "b")
				aFsys := rwos.DirFS(aDir)
				bFsys := rwos.DirFS(bDir)
				aIndex, err := v2.NewIndex(aFsys)
				require.NoError(t, err)
				bIndex, err := v2.NewIndex(bFsys)
				require.NoError(t, err)

				err = Validate(context.Background(), ValidateOptions{
					AdvisoryDocs:     bIndex,
					BaseAdvisoryDocs: aIndex,
					Now:              now,
				})
				if tt.shouldBeValid && err != nil {
					t.Errorf("should be valid but got error: %v", err)
				}
				if !tt.shouldBeValid && err == nil {
					t.Error("shouldn't be valid but got no error")
				}
			})
		}
	})

	t.Run("alias completeness", func(t *testing.T) {
		cases := []struct {
			name          string
			shouldBeValid bool
		}{
			{
				name:          "alias-missing-cve",
				shouldBeValid: false,
			},
			{
				name:          "alias-missing-ghsa",
				shouldBeValid: false,
			},
			{
				name:          "alias-not-missing",
				shouldBeValid: true,
			},
		}

		mockAF := &mockAliasFinder{
			cveByGHSA: map[string]string{
				"GHSA-2222-2222-2222": "CVE-2222-2222",
			},
			ghsasByCVE: map[string][]string{
				"CVE-2222-2222": {"GHSA-2222-2222-2222"},
			},
		}

		for _, tt := range cases {
			t.Run(tt.name, func(t *testing.T) {
				dir := filepath.Join("testdata", "validate", tt.name)
				fsys := rwos.DirFS(dir)
				index, err := v2.NewIndex(fsys)
				require.NoError(t, err)

				err = Validate(context.Background(), ValidateOptions{
					AdvisoryDocs: index,
					AliasFinder:  mockAF,
				})
				if tt.shouldBeValid && err != nil {
					t.Errorf("should be valid but got error: %v", err)
				}
				if !tt.shouldBeValid && err == nil {
					t.Error("shouldn't be valid but got no error")
				}
			})
		}
	})

	t.Run("package existence", func(t *testing.T) {
		cases := []struct {
			name          string
			packageSet    map[string]struct{}
			shouldBeValid bool
		}{
			{
				name:          "package-exists",
				packageSet:    map[string]struct{}{"ko": {}},
				shouldBeValid: true,
			},
			{
				name:          "package-does-not-exist",
				packageSet:    map[string]struct{}{"mo": {}},
				shouldBeValid: false,
			},
		}

		advIndex, err := v2.NewIndex(rwos.DirFS(filepath.Join("testdata", "validate", "package-existence", "advisories")))
		require.NoError(t, err)
		packageIndex, err := build.NewIndex(rwos.DirFS(filepath.Join("testdata", "validate", "package-existence", "distro")))
		require.NoError(t, err)

		for _, tt := range cases {
			t.Run(tt.name, func(t *testing.T) {
				err = Validate(context.Background(), ValidateOptions{
					AdvisoryDocs:          advIndex,
					SelectedPackages:      tt.packageSet,
					PackageConfigurations: packageIndex,
				})
				if tt.shouldBeValid && err != nil {
					t.Errorf("should be valid but got error: %v", err)
				}
				if !tt.shouldBeValid && err == nil {
					t.Error("shouldn't be valid but got no error")
				}
			})
		}
	})
}
