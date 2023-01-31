package stringhelpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRegexpSplit(t *testing.T) {
	tests := []struct {
		input     string
		separator string
		expected  []string
	}{
		{
			"foo/bar", ":|/", []string{"foo", "bar"},
		},
		{
			"foo:bar", ":|/", []string{"foo", "bar"},
		},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			actual := RegexpSplit(test.input, test.separator)
			assert.Equal(t, test.expected, actual, "split did not match for input %s with separator %s", test.input, test.separator)
		})
	}
}
