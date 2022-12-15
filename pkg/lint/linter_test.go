package lint

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func newTestLinterWithDir(path string) *Linter {
	return New(WithPath(filepath.Join("testdata", path)))
}

func newTestLinterWithFile(path string) *Linter {
	return New(WithPath(filepath.Join("testdata/files/", path)))
}

func TestLinter_Dir(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    Result
		wantErr bool
	}{
		{
			name: "valid directory",
			path: "dir/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := newTestLinterWithDir(tt.path)
			got, err := l.Lint()
			if (err != nil) != tt.wantErr {
				t.Errorf("Lint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			assert.NoError(t, err)
			assert.Empty(t, got)
		})
	}
}
