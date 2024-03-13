package advisory

import (
	"context"
	"path/filepath"
	"testing"

	"chainguard.dev/melange/pkg/config"
	"github.com/chainguard-dev/go-apk/pkg/apk"
	"github.com/stretchr/testify/require"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/configs/build"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func TestValidate(t *testing.T) {
	// The diff validation tests use the test fixtures for advisory.IndexDiff.

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
				aIndex, err := v2.NewIndex(context.Background(), aFsys)
				require.NoError(t, err)
				bIndex, err := v2.NewIndex(context.Background(), bFsys)
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

		t.Run("with existence conditions", func(t *testing.T) {
			cases := []struct {
				name            string
				subcase         string
				packageCfgsFunc func(t *testing.T) *configs.Index[config.Configuration]
				apkindex        *apk.APKIndex
				shouldBeValid   bool
			}{
				{
					name:            "added-document", // these must be in distro
					subcase:         "package in APKINDEX but not distro",
					packageCfgsFunc: distroWithNothing,
					apkindex: &apk.APKIndex{
						Packages: []*apk.Package{
							{
								Name: "ko",
							},
						},
					},
					shouldBeValid: false,
				},
				{
					name:            "added-document",
					subcase:         "package in distro and APKINDEX",
					packageCfgsFunc: distroWithKo,
					apkindex: &apk.APKIndex{
						Packages: []*apk.Package{
							{
								Name:    "kaf",
								Version: "0.2.6-r5",
							},
							{
								Name:    "kaf",
								Version: "0.2.6-r6",
							},
							{
								Name: "ko",
							},
						},
					},
					shouldBeValid: true,
				},
				{
					name:            "added-document",
					subcase:         "package not in distro or APKINDEX",
					packageCfgsFunc: distroWithNothing,
					apkindex: &apk.APKIndex{
						Packages: []*apk.Package{
							{
								Name:    "kaf",
								Version: "0.2.6-r5",
							},
							{
								Name:    "kaf",
								Version: "0.2.6-r6",
							},
						},
					},
					shouldBeValid: false,
				},
				{
					name:            "added-advisory", // i.e. "modified-document", can be just in APKINDEX
					subcase:         "package in APKINDEX but not distro",
					packageCfgsFunc: distroWithNothing,
					apkindex: &apk.APKIndex{
						Packages: []*apk.Package{
							{
								Name: "ko",
							},
						},
					},
					shouldBeValid: true,
				},
				{
					name:            "added-advisory",
					subcase:         "package in distro and APKINDEX",
					packageCfgsFunc: distroWithKo,
					apkindex: &apk.APKIndex{
						Packages: []*apk.Package{
							{
								Name: "ko",
							},
						},
					},
					shouldBeValid: true,
				},
				{
					name:            "added-advisory",
					subcase:         "package not in distro or APKINDEX",
					packageCfgsFunc: distroWithNothing,
					apkindex:        &apk.APKIndex{},
					shouldBeValid:   false,
				},
			}

			for _, tt := range cases {
				t.Run(tt.name+" -- "+tt.subcase, func(t *testing.T) {
					aDir := filepath.Join("testdata", "diff", tt.name, "a")
					bDir := filepath.Join("testdata", "diff", tt.name, "b")
					aFsys := rwos.DirFS(aDir)
					bFsys := rwos.DirFS(bDir)
					aIndex, err := v2.NewIndex(context.Background(), aFsys)
					require.NoError(t, err)
					bIndex, err := v2.NewIndex(context.Background(), bFsys)
					require.NoError(t, err)

					err = Validate(context.Background(), ValidateOptions{
						AdvisoryDocs:          bIndex,
						BaseAdvisoryDocs:      aIndex,
						Now:                   now,
						PackageConfigurations: tt.packageCfgsFunc(t),
						APKIndex:              tt.apkindex,
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
				index, err := v2.NewIndex(context.Background(), fsys)
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

	t.Run("fixed versions", func(t *testing.T) {
		t.Run("must exist in APKINDEX", func(t *testing.T) {
			cases := []struct {
				name          string
				apkindex      *apk.APKIndex
				shouldBeValid bool
			}{
				{
					name: "package-missing",
					apkindex: &apk.APKIndex{
						Packages: nil,
					},
					shouldBeValid: false,
				},
				{
					name: "fixed-version-missing",
					apkindex: &apk.APKIndex{
						Packages: []*apk.Package{
							{
								Name:    "ko",
								Version: "1.0.0-r1",
							},
						},
					},
					shouldBeValid: false,
				},
				{
					name: "fixed-version-present-and-first", // which is not allowed
					apkindex: &apk.APKIndex{
						Packages: []*apk.Package{
							{
								Name:    "ko",
								Version: "1.0.0-r2",
							},
						},
					},
					shouldBeValid: false,
				},
				{
					name: "fixed-version-present-and-not-first",
					apkindex: &apk.APKIndex{
						Packages: []*apk.Package{
							{
								Name:    "ko",
								Version: "1.0.0-r1",
							},
							{
								Name:    "ko",
								Version: "1.0.0-r2",
							},
							{
								Name:    "mo",
								Version: "1.0.0-r8",
							},
							{
								Name:    "mo",
								Version: "1.0.0-r9",
							},
							{
								Name:    "mo",
								Version: "1.0.0-r10",
							},
						},
					},
					shouldBeValid: true,
				},
				{
					name: "fixed-version-present-and-not-first-missing-rs",
					apkindex: &apk.APKIndex{
						Packages: []*apk.Package{
							{
								Name:    "ko",
								Version: "1.0.0-r1",
							},
							{
								Name:    "ko",
								Version: "1.0.0-r2",
							},
							{
								Name:    "mo",
								Version: "1.0.0-r8",
							},
							{
								Name:    "mo",
								Version: "1.0.0-r9",
							},
							{
								Name:    "mo",
								Version: "1.0.0-r10",
							},
						},
					},
					shouldBeValid: true,
				},
			}

			for _, tt := range cases {
				t.Run(tt.name, func(t *testing.T) {
					dir := filepath.Join("testdata", "validate", "fixed-version")
					fsys := rwos.DirFS(dir)
					index, err := v2.NewIndex(context.Background(), fsys)
					require.NoError(t, err)

					err = Validate(context.Background(), ValidateOptions{
						AdvisoryDocs: index,
						APKIndex:     tt.apkindex,
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
	})

	t.Run("duplicate advisories", func(t *testing.T) {
		cases := []struct {
			name          string
			shouldBeValid bool
		}{
			{
				name:          "duplicate-advisory-by-id",
				shouldBeValid: false,
			},
			{
				name:          "duplicate-advisory-by-id-and-alias",
				shouldBeValid: false,
			},
			{
				name:          "no-duplicates",
				shouldBeValid: true,
			},
		}

		for _, tt := range cases {
			t.Run(tt.name, func(t *testing.T) {
				dir := filepath.Join("testdata", "validate", tt.name)
				fsys := rwos.DirFS(dir)
				index, err := v2.NewIndex(context.Background(), fsys)
				require.NoError(t, err)

				err = Validate(context.Background(), ValidateOptions{
					AdvisoryDocs: index,
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

func distroWithKo(t *testing.T) *configs.Index[config.Configuration] {
	fsys := rwos.DirFS(filepath.Join("testdata", "validate", "package-existence", "distro"))
	index, err := build.NewIndex(context.Background(), fsys)
	require.NoError(t, err)
	return index
}

func distroWithNothing(t *testing.T) *configs.Index[config.Configuration] {
	fsys := rwos.DirFS(filepath.Join("testdata", "validate", "package-existence", "distro-empty"))
	index, err := build.NewIndex(context.Background(), fsys)
	require.NoError(t, err)
	return index
}
