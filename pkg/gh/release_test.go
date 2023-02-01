package gh

import (
	"testing"

	"github.com/hashicorp/go-version"
	"github.com/stretchr/testify/assert"
)

func TestPrereleaseBump(t *testing.T) {
	tests := []struct {
		current  string
		expected string
		ReleaseOptions
	}{
		{
			current: "v1", expected: "v1.0.1ab1",
			ReleaseOptions: ReleaseOptions{
				BumpPrereleaseWithPrefix: "ab",
			},
		},
		{
			current: "v1.2", expected: "v1.2.1ab1",
			ReleaseOptions: ReleaseOptions{
				BumpPrereleaseWithPrefix: "ab",
			},
		},
		{
			current: "v1.2.3", expected: "v1.2.4ab1",
			ReleaseOptions: ReleaseOptions{
				BumpPrereleaseWithPrefix: "ab",
			},
		},
		{
			current: "v1.2.4ab1", expected: "v1.2.4ab2",
			ReleaseOptions: ReleaseOptions{
				BumpPrereleaseWithPrefix: "ab",
			},
		},
		{
			current: "v1.2.4ab10", expected: "v1.2.4ab11",
			ReleaseOptions: ReleaseOptions{
				BumpPrereleaseWithPrefix: "ab",
			},
		},
		{
			current: "v1.2.4ab12", expected: "v1.2.4ab13",
			ReleaseOptions: ReleaseOptions{
				BumpPrereleaseWithPrefix: "ab",
			},
		},
		{
			current: "v0.0.0", expected: "v0.0.1ab1",
			ReleaseOptions: ReleaseOptions{
				BumpPrereleaseWithPrefix: "ab",
			},
		},
		{
			current: "v1.0.0", expected: "v2.0.0",
			ReleaseOptions: ReleaseOptions{
				BumpMajor: true,
			},
		},
		{
			current: "v1.1.0", expected: "v1.2.0",
			ReleaseOptions: ReleaseOptions{
				BumpMinor: true,
			},
		},
		{
			current: "v1.0.1", expected: "v1.0.2",
			ReleaseOptions: ReleaseOptions{
				BumpPatch: true,
			},
		},
		{
			current: "v1.0.1", expected: "v1.0.2ab1",
			ReleaseOptions: ReleaseOptions{
				BumpPatch:                true,
				BumpPrereleaseWithPrefix: "ab",
			},
		},
		{
			current: "v1.0.10ab10", expected: "v1.0.10ab11",
			ReleaseOptions: ReleaseOptions{
				BumpPrereleaseWithPrefix: "ab",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.current, func(t *testing.T) {
			c, err := version.NewVersion(test.current)
			assert.NoError(t, err)
			e, err := version.NewVersion(test.expected)
			assert.NoError(t, err)

			got, err := test.ReleaseOptions.bumpReleaseVersion(c)
			assert.NoError(t, err)

			assert.Equal(t, e.Original(), got.Original())
		})
	}
}
