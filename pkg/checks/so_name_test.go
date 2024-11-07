package checks

import (
	"archive/tar"
	"bytes"
	"fmt"
	"testing"

	goapk "chainguard.dev/apko/pkg/apk/apk"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

func TestChecks_getSonameFiles(t *testing.T) {
	for _, tt := range []struct {
		name        string
		sonameFiles []string
		dtSoname    []string
		want        []string
	}{{
		name: "match",
		sonameFiles: []string{
			"foo.so", // should not match
			"foo.so.1",
			"foo.so.11",
			"foo.so.1.1",
			"libstdc++.so.6.0.30-gdb.py",
		},
		dtSoname: []string{"cheese.so.1.1"},
		want: []string{
			"foo.so.1",
			"foo.so.11",
			"foo.so.1.1",
			"libstdc++.so.6.0.30-gdb.py",
			"cheese.so.1.1",
		},
	}, {
		name: "dont_match",
		sonameFiles: []string{
			"foo",
			"XIDefineCursor.3",
			"README.solaris2",
		},
		want: nil,
	}} {
		t.Run(tt.name, func(t *testing.T) {
			o := SoNameOptions{}

			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			for _, f := range tt.sonameFiles {
				hdr := &tar.Header{
					Name: "dir/" + f,
					Mode: 0o644,
					Size: int64(len("test")),
				}
				err := tw.WriteHeader(hdr)
				assert.NoError(t, err)
				_, err = tw.Write([]byte("test"))
				assert.NoError(t, err)
			}

			// simulate DT_SONAME
			for _, f := range tt.dtSoname {
				hdr := &tar.Header{
					Name: "dir/" + f,
					Mode: 0o644,
					Size: int64(len("test")),
				}
				err := tw.WriteHeader(hdr)
				assert.NoError(t, err)
				_, err = tw.Write([]byte("test"))
				assert.NoError(t, err)
			}
			assert.NoError(t, tw.Close())

			tr := tar.NewReader(&buf)

			got, err := o.getSonameFiles(tr)
			assert.NoError(t, err)

			if d := cmp.Diff(got, tt.want); d != "" {
				t.Errorf("getSonameFiles() mismatch (-got +want):\n%s", d)
			}
		})
	}
}

func TestSoNameOptions_checkSonamesMatch(t *testing.T) {
	ctx := slogtest.Context(t)
	tests := []struct {
		name                string
		existingSonameFiles []string
		newSonameFiles      []string
		wantErr             assert.ErrorAssertionFunc
	}{
		{
			name: "deleted", existingSonameFiles: []string{"foo.so", "bar.so"}, newSonameFiles: []string{"foo.so"},
			wantErr: assert.NoError,
		},
		{
			name: "match", existingSonameFiles: []string{"foo.so", "bar.so"}, newSonameFiles: []string{"foo.so", "bar.so"},
			wantErr: assert.NoError,
		},
		{
			name: "ignore", existingSonameFiles: []string{"foo.so"}, newSonameFiles: []string{"foo.so.1"},
			wantErr: assert.NoError,
		},
		{
			name: "match", existingSonameFiles: []string{"foo.so.1"}, newSonameFiles: []string{"foo.so.1"},
			wantErr: assert.NoError,
		},
		{
			name: "match_multiple", existingSonameFiles: []string{"foo.so.1", "bar.so.2"}, newSonameFiles: []string{"foo.so.1", "bar.so.2"},
			wantErr: assert.NoError,
		},
		{
			name: "match_multiple_different_order", existingSonameFiles: []string{"bar.so.2", "foo.so.1"}, newSonameFiles: []string{"foo.so.1", "bar.so.2"},
			wantErr: assert.NoError,
		},
		{
			name: "single_fail", existingSonameFiles: []string{"foo.so.1"}, newSonameFiles: []string{"foo.so.2"},
			wantErr: assert.Error,
		},
		{
			name: "multi_fail", existingSonameFiles: []string{"foo.so.1", "bar.so.1"}, newSonameFiles: []string{"foo.so.1", "bar.so.2"},
			wantErr: assert.Error,
		},
		{
			name: "skip_new", existingSonameFiles: []string{"foo.so.1", "bar.so.1"}, newSonameFiles: []string{"cheese.so.1"},
			wantErr: assert.NoError,
		},
		{
			name: "abi_compatible", existingSonameFiles: []string{"foo.so.1.2"}, newSonameFiles: []string{"foo.so.1.3"},
			wantErr: assert.NoError,
		},
		{
			name: "no_existing", existingSonameFiles: []string{}, newSonameFiles: []string{"cheese.so.1"},
			wantErr: assert.NoError,
		},
		{
			name: "none_at_all", existingSonameFiles: []string{}, newSonameFiles: []string{},
			wantErr: assert.NoError,
		},
		{
			name: "complex_chars_with_qualifier", existingSonameFiles: []string{"libstdc++.so.6.0.30-gdb.py"}, newSonameFiles: []string{"libstdc++.so.6.0.30-gdb.py"},
			wantErr: assert.NoError,
		},
		{
			name: "ignore_non_standard_version_suffix", existingSonameFiles: []string{"libgs.so.10.02.debug"}, newSonameFiles: []string{"libgs.so.10.02.debug"},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := SoNameOptions{}
			existingPackages := map[string]*goapk.Package{}
			tt.wantErr(t, o.checkSonamesMatch(ctx, existingPackages, tt.existingSonameFiles, tt.newSonameFiles), fmt.Sprintf("checkSonamesMatch(%v, %v)", tt.existingSonameFiles, tt.newSonameFiles))
		})
	}
}

func TestSoNameOptions_checkSonamesSubFolders(t *testing.T) {
	o := SoNameOptions{}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{
		Name: "foo/bar/baz/bar.so.1.2.3",
		Mode: 0o644,
		Size: int64(len("test")),
	}
	err := tw.WriteHeader(hdr)
	assert.NoError(t, err)
	_, err = tw.Write([]byte("test"))
	assert.NoError(t, err)

	tr := tar.NewReader(&buf)
	got, err := o.getSonameFiles(tr)
	assert.NoError(t, err)

	assert.Equal(t, "bar.so.1.2.3", got[0])
}
