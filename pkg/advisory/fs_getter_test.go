package advisory

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
)

func TestFSGetter(t *testing.T) {
	ctx := t.Context()
	g := NewFSGetter(os.DirFS(filepath.Join("testdata", "fs_getter")))

	t.Run("PackageNames", func(t *testing.T) {
		names, err := g.PackageNames(ctx)
		require.NoError(t, err)

		expected := []string{"brotli"}
		assert.Equal(t, expected, names)
	})

	t.Run("Advisories", func(t *testing.T) {
		t.Run("found", func(t *testing.T) {
			actual, err := g.Advisories(ctx, "brotli")
			require.NoError(t, err)

			testTime := v2.Timestamp(time.Date(2022, 9, 15, 2, 40, 18, 0, time.UTC))

			expected := []v2.PackageAdvisory{
				{
					PackageName: "brotli",
					Advisory: v2.Advisory{
						ID: "CGA-xxxx-xxxx-xxxx",
						Aliases: []string{
							"CVE-2020-8927",
						},
						Events: []v2.Event{{
							Timestamp: testTime,
							Type:      v2.EventTypeFixed,
							Data: v2.Fixed{
								FixedVersion: "1.0.9-r0",
							},
						},
						},
					},
				},
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Fatalf("unexpected advisories (-want +got):\n%s", diff)
			}
		})

		t.Run("not found", func(t *testing.T) {
			_, err := g.Advisories(ctx, "not-found")
			assert.NoError(t, err)
		})
	})
}
