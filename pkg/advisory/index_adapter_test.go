package advisory

import (
	"path/filepath"
	"testing"
	"time"

	v2 "github.com/chainguard-dev/advisory-schema/pkg/advisory/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	adv2 "github.com/wolfi-dev/wolfictl/pkg/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func Test_indexAdapter(t *testing.T) {
	ctx := t.Context()

	fsys := rwos.DirFS(filepath.Join("testdata", "index_adapter", "advisories"))
	index, err := adv2.NewIndex(ctx, fsys)
	require.NoError(t, err)

	adapter := AdaptIndex(index)

	t.Run("PackageNames", func(t *testing.T) {
		names, err := adapter.PackageNames(ctx)
		require.NoError(t, err)

		expected := []string{
			"brotli",
			"ko",
			"openssl",
		}

		if diff := cmp.Diff(expected, names); diff != "" {
			t.Errorf("PackageNames() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("Advisories", func(t *testing.T) {
		advisories, err := adapter.Advisories(ctx, "ko")
		require.NoError(t, err)

		testTime, err := time.Parse(time.RFC3339, "2023-05-04T14:34:34Z")
		require.NoError(t, err)

		expected := []v2.PackageAdvisory{
			{
				PackageName: "ko",
				Advisory: v2.Advisory{
					ID:      "CGA-5f5c-53mg-6p2v",
					Aliases: []string{"GHSA-33pg-m6jh-5237"},
					Events: []v2.Event{
						{
							Timestamp: v2.Timestamp(testTime),
							Type:      v2.EventTypeFixed,
							Data: v2.Fixed{
								FixedVersion: "0.13.0-r3",
							},
						},
					},
				},
			},
			{
				PackageName: "ko",
				Advisory: v2.Advisory{
					ID:      "CGA-4j8r-gcwr-9w6v",
					Aliases: []string{"GHSA-232p-vwff-86mp"},
					Events: []v2.Event{
						{
							Timestamp: v2.Timestamp(testTime),
							Type:      v2.EventTypeFixed,
							Data: v2.Fixed{
								FixedVersion: "0.13.0-r5",
							},
						},
					},
				},
			},
		}

		if diff := cmp.Diff(expected, advisories); diff != "" {
			t.Errorf("Advisories() mismatch (-want +got):\n%s", diff)
		}
	})
}
