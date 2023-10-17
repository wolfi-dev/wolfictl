package buildlog

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	f, err := os.Open("testdata/packages.log")
	if err != nil {
		t.Fatalf("unable to open test data: %v", err)
	}
	defer f.Close()

	expected := []Entry{
		{
			Arch:        "aarch64",
			Origin:      "tekton-chains",
			Package:     "tekton-chains",
			FullVersion: "0.18.0-r3",
		},
		{
			Arch:        "aarch64",
			Origin:      "jansson",
			Package:     "jansson",
			FullVersion: "2.14-r0",
		},
		{
			Arch:        "aarch64",
			Origin:      "jansson",
			Package:     "jansson-dev",
			FullVersion: "2.14-r0",
		},
	}

	actual, err := Parse(f)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}
