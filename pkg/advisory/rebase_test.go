package advisory

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os/memfs"
	"github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os/testerfs"
)

func TestRebase(t *testing.T) {
	// For observing interactions with the test filesystem. Change the log-level to
	// whatever's useful for you.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Test cases:
	// - Many advisories but just one selected
	// - One selected, but it's a detection, so don't copy anything

	cases := []struct {
		name      string // also used as the test case directory name (spaces are replaced with dashes)
		vulnID    string
		assertErr assert.ErrorAssertionFunc
	}{
		{
			name:      "dst adv unresolved",
			assertErr: assert.NoError,
		},
		{
			name:      "dst adv resolved",
			assertErr: assert.NoError,
		},
		{
			name:      "dst adv does not exist but doc does",
			assertErr: assert.NoError,
		},
		{
			name:      "dst adv and doc do not exist",
			assertErr: assert.NoError,
		},
		{
			name:      "single src adv selected",
			vulnID:    "CVE-2023-1234",
			assertErr: assert.NoError,
		},
		{
			name:      "single src adv selected but it's a detection",
			vulnID:    "CVE-2023-1234",
			assertErr: assert.NoError,
		},
		{
			name:      "nonexistent src adv selected",
			vulnID:    "CVE-9999-9999",
			assertErr: assert.Error,
		},
	}

	expectedNewAdvID := "CGA-zzzz-zzzz-zzzz"
	DefaultIDGenerator = StaticIDGenerator{ID: expectedNewAdvID}
	defer func() { DefaultIDGenerator = &RandomIDGenerator{} }()

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			// "Arrange"

			ctx := context.Background()
			testCaseDir := filepath.Join("testdata", "rebase", strings.ReplaceAll(tt.name, " ", "-"))

			srcDir := filepath.Join(testCaseDir, "src")
			srcFsys := memfs.New(os.DirFS(srcDir))
			srcIndex, err := v2.NewIndex(ctx, srcFsys)
			if err != nil {
				t.Fatalf("creating advisory index for source directory %q: %v", srcDir, err)
			}

			dstDir := filepath.Join(testCaseDir, "dst")
			dstFsys, err := testerfs.NewWithLogger(os.DirFS(dstDir), logger)
			if err != nil {
				t.Fatalf("creating test fixture filesystem for destination directory %q: %v", dstDir, err)
			}
			dstIndex, err := v2.NewIndex(ctx, dstFsys)
			if err != nil {
				t.Fatalf("creating advisory index for destination directory %q: %v", dstDir, err)
			}

			// We'll use fixed times for the sake of a deterministic test. Here's how we'll expect things to work...
			//
			// - The earliest time in existence will be the "baseline" time.
			// - The first events in our test fixture advisory files should use this baseline time.
			// - Each successive event in the test fixture should increment the date by one day.
			// - The "current time" (used by the Rebase opts) should be the baseline time plus 1 year.
			// - So, this "current time" is what we'd expect to be used in newly added events on the destination file.

			baselineTime := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
			const packageName = "brotli" // Package used for all test cases.
			vulnID := "CVE-2023-1234"    // Default used for most test cases.
			if tt.vulnID != "" {
				vulnID = tt.vulnID
			}

			opts := RebaseOptions{
				SourceIndex:      srcIndex,
				DestinationIndex: dstIndex,
				PackageName:      packageName,
				VulnerabilityID:  vulnID,
				CurrentTime:      v2.Timestamp(baselineTime.AddDate(1, 0, 0)),
			}

			// "Act"

			err = Rebase(ctx, opts)

			// "Assert"

			tt.assertErr(t, err)
			if diff := dstFsys.DiffAll(); diff != "" {
				t.Errorf("unexpected diff:\n%s", diff)
			}
		})
	}
}
