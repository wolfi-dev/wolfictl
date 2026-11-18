package lint

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestLineOf(t *testing.T) {
	const doc = `package:
  name: foo
  version: 1.0.0
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/foo.tar.gz
  - runs: |
      echo hello
`
	var root yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(doc), &root))

	tests := []struct {
		name string
		path []any
		want int
	}{
		{name: "mapping key", path: []any{"package"}, want: 1},
		{name: "nested mapping key", path: []any{"package", "version"}, want: 3},
		{name: "sequence item", path: []any{"pipeline", 1}, want: 8},
		{name: "key of a block value", path: []any{"pipeline", 1, "runs"}, want: 8},
		{name: "key in sequence item", path: []any{"pipeline", 0, "with", "uri"}, want: 7},
		{name: "missing key falls back to parent", path: []any{"pipeline", 0, "with", "expected-sha256"}, want: 6},
		{name: "out of range index falls back to parent", path: []any{"pipeline", 2, "runs"}, want: 4},
		{name: "key on a sequence falls back to parent", path: []any{"pipeline", "runs"}, want: 4},
		{name: "index on a mapping falls back to parent", path: []any{"package", 0}, want: 1},
		{name: "missing top-level key", path: []any{"update"}, want: 0},
		{name: "empty path", path: nil, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, lineOf(&root, tt.path...))
		})
	}

	t.Run("nil root", func(t *testing.T) {
		assert.Equal(t, 0, lineOf(nil, "package"))
	})
}

func TestErrorLine(t *testing.T) {
	err := &positionedError{line: 42, err: errors.New("boom")}

	assert.Equal(t, 42, errorLine(err))
	assert.Equal(t, 42, errorLine(fmt.Errorf("wrapped: %w", err)))
	assert.Equal(t, 0, errorLine(errors.New("boom")))
	assert.Equal(t, "boom", err.Error())
}
