package advisory

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cgaid "github.com/chainguard-dev/advisory-schema/pkg/advisory"
	v2 "github.com/chainguard-dev/advisory-schema/pkg/advisory/v2"
	"github.com/chainguard-dev/yam/pkg/yam/formatted"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os/testerfs"
)

func TestFSPutter_Upsert(t *testing.T) {
	ctx := t.Context()
	testTime := v2.Timestamp(time.Date(2022, 9, 15, 2, 40, 18, 0, time.UTC))

	cases := []struct {
		name                 string
		req                  Request
		skipFsysConstruction bool // don't bother with a test fsys since we expect a failure before fsys access
		expectedID           string
		assertErr            assert.ErrorAssertionFunc
	}{
		{
			name: "no package name",
			req: Request{
				Package: "",
			},
			skipFsysConstruction: true,
			assertErr:            assert.Error,
		},
		{
			name: "package name with nonexistent advisory ID",
			req: Request{
				Package:    "foo",
				AdvisoryID: "CGA-4444-4444-4444",
			},
			assertErr: assert.Error,
		},
		{
			name: "no-op update",
			req: Request{
				Package:    "foo",
				AdvisoryID: "CGA-2222-2222-2222",
				Aliases:    nil,
				Event:      v2.Event{},
			},
			expectedID: "CGA-2222-2222-2222",
			assertErr:  assert.NoError,
		},
		{
			name: "just update aliases",
			req: Request{
				Package:    "foo",
				AdvisoryID: "CGA-2222-2222-2222",
				Aliases:    []string{"GHSA-xxxx-xxxx-xxxx"},
				Event:      v2.Event{},
			},
			expectedID: "CGA-2222-2222-2222",
			assertErr:  assert.NoError,
		},
		{
			name: "create when no document exists",
			req: Request{
				Package: "foo",
				Aliases: []string{"CVE-2020-8927"},
				Event: v2.Event{
					Timestamp: testTime,
					Type:      v2.EventTypeFixed,
					Data: v2.Fixed{
						FixedVersion: "1.0.9-r0",
					},
				},
			},
			expectedID: "CGA-2222-2222-2222",
			assertErr:  assert.NoError,
		},
		{
			name: "create when document exists but not advisory",
			req: Request{
				Package: "foo",
				Aliases: []string{"CVE-2020-8927"},
				Event: v2.Event{
					Timestamp: testTime,
					Type:      v2.EventTypeFixed,
					Data: v2.Fixed{
						FixedVersion: "1.0.9-r0",
					},
				},
			},
			expectedID: "CGA-2222-2222-2222",
			assertErr:  assert.NoError,
		},
		{
			name: "update",
			req: Request{
				Package:    "foo",
				AdvisoryID: "CGA-2222-2222-2222",
				Aliases:    []string{"CVE-2020-8927"},
				Event: v2.Event{
					Timestamp: testTime,
					Type:      v2.EventTypePendingUpstreamFix,
					Data: v2.PendingUpstreamFix{
						Note: "this is a note",
					},
				},
			},
			expectedID: "CGA-2222-2222-2222",
			assertErr:  assert.NoError,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			testDir := filepath.Join("testdata", "fs_putter", strings.ReplaceAll(tt.name, " ", "-"))

			var fsys *testerfs.FS
			var err error
			if !tt.skipFsysConstruction {
				fsys, err = testerfs.New(os.DirFS(testDir))
				require.NoError(t, err)
			}

			var enc DocumentEncoder = func(w io.Writer, doc v2.Document) error {
				encoder := formatted.NewEncoder(w)

				// Set up the formatting options we expect
				encoder = encoder.SetIndent(2)
				encoder, err = encoder.SetGapExpressions(".", ".advisories")
				require.NoError(t, err)

				return encoder.Encode(doc)
			}

			p := &FSPutter{
				fsys:        fsys,
				enc:         enc,
				idGenerator: cgaid.StaticIDGenerator{ID: "CGA-2222-2222-2222"},
			}

			id, err := p.Upsert(ctx, tt.req)
			tt.assertErr(t, err)

			if tt.expectedID != id {
				t.Errorf("expected ID result to be %q, got %q", tt.expectedID, id)
			}

			if err == nil {
				if diff := fsys.DiffAll(); diff != "" {
					t.Errorf("filesystem in an unexpected state (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestNewFSPutterWithAutomaticEncoder(t *testing.T) {
	cases := []string{
		"with-config-file",
		"without-config-file",
	}

	testTime := v2.Timestamp(time.Date(2025, 3, 11, 2, 40, 18, 0, time.UTC))

	for _, tt := range cases {
		t.Run(tt, func(t *testing.T) {
			ctx := t.Context()
			testDir := filepath.Join("testdata", "fs_putter", "automatic-encoder", tt)

			fsys, err := testerfs.New(os.DirFS(testDir))
			require.NoError(t, err, "creating test filesystem")

			p := NewFSPutterWithAutomaticEncoder(fsys) // (we want to test this constructor specifically)
			require.NotNil(t, p, "creating FSPutter")

			req := Request{
				Package:    "foo",
				AdvisoryID: "CGA-xvg9-g29c-rr68",
				Event: v2.Event{
					Timestamp: testTime,
					Type:      v2.EventTypeFixed,
					Data: v2.Fixed{
						FixedVersion: "1.2.3-r4",
					},
				},
			}

			// We're upserting just so that we can see if `NewFSPutterWithAutomaticEncoder`
			// set up the encoder correctly (when YAML data is written to the filesystem).

			_, err = p.Upsert(ctx, req)
			require.NoError(t, err, "upserting advisory data")

			if diff := fsys.DiffAll(); diff != "" {
				t.Errorf("filesystem in an unexpected state (-want +got):\n%s", diff)
			}
		})
	}
}
