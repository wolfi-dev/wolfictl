package advisory

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func TestValidate(t *testing.T) {
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

			err = Validate(ValidateOptions{
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
}

// now establishes a fixed time for testing recency validation, for deterministic test runs.
var now = time.Unix(1699660800, 0) // Nov 11 2023 00:00:00 UTC
