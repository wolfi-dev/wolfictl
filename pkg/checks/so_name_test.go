package checks

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChecks_getSonameFiles(t *testing.T) {
	tests := []struct {
		name        string
		sonameFiles []string
		dtSoname    []string
		match       bool
		wantErr     assert.ErrorAssertionFunc
	}{
		{
			name: "match", sonameFiles: []string{
				"foo.so",
				"foo.so.1",
				"foo.so.11",
				"foo.so.1.1",
				"libstdc++.so.6.0.30-gdb.py",
			}, dtSoname: []string{"cheese.so.1.1"}, match: true,
			wantErr: assert.NoError,
		},
		{
			name: "dont_match", sonameFiles: []string{
				"foo",
				"XIDefineCursor.3",
				"README.solaris2",
			}, match: false,
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := SoNameOptions{}

			dir := t.TempDir()

			for _, f := range tt.sonameFiles {
				err := os.WriteFile(filepath.Join(dir, f), []byte("test"), os.ModePerm)
				assert.NoError(t, err)
			}

			// simulate DT_SONAME
			for _, f := range tt.dtSoname {
				err := os.WriteFile(filepath.Join(dir, f), []byte("test"), os.ModePerm)
				assert.NoError(t, err)
				err = os.Link(filepath.Join(dir, f), filepath.Join(dir, "cheese.so.1"))
				assert.NoError(t, err)
			}

			got, err := o.getSonameFiles(dir)
			assert.NoError(t, err)

			expectedCount := 0
			if tt.match {
				expectedCount = len(tt.sonameFiles) + len(tt.dtSoname)
			}

			assert.Equal(t, expectedCount, len(got))
		})
	}
}

func TestSoNameOptions_checkSonamesMatch(t *testing.T) {
	tests := []struct {
		name                string
		existingSonameFiles map[string][]string
		newSonameFiles      map[string][]string
		wantErr             bool
	}{
		{
			name:                "deleted",
			existingSonameFiles: map[string][]string{"foo": {"so"}, "bar": {"so"}},
			newSonameFiles:      map[string][]string{"foo": {"so"}},
			wantErr:             false,
		},
		{
			name:                "match",
			existingSonameFiles: map[string][]string{"foo": {"so"}, "bar": {"so"}},
			newSonameFiles:      map[string][]string{"foo": {"so"}, "bar": {"so"}},
			wantErr:             false,
		},
		{
			name:                "ignore",
			existingSonameFiles: map[string][]string{"foo": {"so"}},
			newSonameFiles:      map[string][]string{"foo": {"so.1"}},
			wantErr:             false,
		},
		{
			name:                "match",
			existingSonameFiles: map[string][]string{"foo": {"so.1"}},
			newSonameFiles:      map[string][]string{"foo": {"so.1"}},
			wantErr:             false,
		},
		{
			name:                "match_multiple",
			existingSonameFiles: map[string][]string{"foo": {"so.1"}, "bar": {"so.2"}},
			newSonameFiles:      map[string][]string{"foo": {"so.1"}, "bar": {"so.2"}},
			wantErr:             false,
		},
		{
			name:                "match_multiple_different_order",
			existingSonameFiles: map[string][]string{"bar": {"so.2"}, "foo": {"so.1"}},
			newSonameFiles:      map[string][]string{"foo": {"so.1"}, "bar": {"so.2"}},
			wantErr:             false,
		},
		{
			name:                "single_fail",
			existingSonameFiles: map[string][]string{"foo": {"so.1"}},
			newSonameFiles:      map[string][]string{"foo": {"so.2"}},
			wantErr:             true,
		},
		{
			name:                "multi_fail",
			existingSonameFiles: map[string][]string{"foo": {"so.1"}, "bar": {"so.1"}},
			newSonameFiles:      map[string][]string{"foo": {"so.1"}, "bar": {"so.2"}},
			wantErr:             true,
		},
		{
			name:                "skip_new",
			existingSonameFiles: map[string][]string{"foo": {"so.1"}, "bar": {"so.1"}},
			newSonameFiles:      map[string][]string{"cheese": {"so.1"}},
			wantErr:             false,
		},
		{
			name:                "abi_compatible",
			existingSonameFiles: map[string][]string{"foo": {"so.1.2"}},
			newSonameFiles:      map[string][]string{"foo": {"so.1.3"}},
			wantErr:             false,
		},
		{
			name:                "no_existing",
			existingSonameFiles: map[string][]string{},
			newSonameFiles:      map[string][]string{"cheese": {"so.1"}},
			wantErr:             false,
		},
		{
			name:                "none_at_all",
			existingSonameFiles: map[string][]string{},
			newSonameFiles:      map[string][]string{},
			wantErr:             false,
		},
		{
			name:                "complex_chars_with_qualifier",
			existingSonameFiles: map[string][]string{"libstdc++": {"so.6.0.30-gdb.py"}},
			newSonameFiles:      map[string][]string{"libstdc++": {"so.6.0.30-gdb.py"}},
			wantErr:             false,
		},
		{
			name:                "ignore_non_standard_version_suffix",
			existingSonameFiles: map[string][]string{"libgs": {"so.10.02.debug"}},
			newSonameFiles:      map[string][]string{"libgs": {"so.10.02.debug"}},
			wantErr:             false,
		},
		{
			name:                "multiple_versions_handled",
			existingSonameFiles: map[string][]string{"libkrb5": {"so.26", "so.3"}},
			newSonameFiles:      map[string][]string{"libkrb5": {"so.26", "so.3"}},
			wantErr:             false,
		},
		{
			name:                "multiple_versions_handled_new_version",
			existingSonameFiles: map[string][]string{"libkrb5": {"so.26", "so.3"}},
			newSonameFiles:      map[string][]string{"libkrb5": {"so.27", "so.3"}},
			wantErr:             true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := SoNameOptions{
				Logger: log.New(log.Writer(), "test: ", log.LstdFlags|log.Lmsgprefix),
			}
			err := o.checkSonamesMatch(tt.existingSonameFiles, tt.newSonameFiles)
			if tt.wantErr {
				assert.Error(t, err, fmt.Sprintf("checkSonamesMatch(%v, %v) should fail", tt.existingSonameFiles, tt.newSonameFiles))
			} else {
				assert.NoError(t, err, fmt.Sprintf("checkSonamesMatch(%v, %v)", tt.existingSonameFiles, tt.newSonameFiles))
			}
		})
	}
}

func TestSoNameOptions_checkSonamesSubFolders(t *testing.T) {
	o := SoNameOptions{}
	dir := t.TempDir()
	subDir := filepath.Join(dir, "foo")
	err := os.Mkdir(subDir, os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}

	filename := "bar.so.1.2.3"
	err = os.WriteFile(filepath.Join(subDir, filename), []byte("test"), os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}

	got, err := o.getSonameFiles(dir)
	assert.NoError(t, err)

	// Check if the map correctly identifies the base name 'bar' and includes the version 'so.1.2.3'
	expected := map[string][]string{
		"bar": {".so.1.2.3"},
	}
	assert.Equal(t, expected, got)
}
