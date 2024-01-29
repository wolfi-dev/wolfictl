package ruby

import (
	"testing"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/wolfi-dev/wolfictl/pkg/melange"
)

func TestIsRubyPackage(t *testing.T) {
	testConfig := config.Configuration{
		Environment: types.ImageConfiguration{
			Contents: types.ImageContents{
				Packages: []string{
					"",
				},
			},
		},
	}
	tests := map[string]struct {
		want  bool
		input string
	}{
		// success cases
		"three_two":     {want: true, input: "ruby-3.2"},
		"three_two_dev": {want: true, input: "ruby-3.2-dev"},

		// failure cases
		"fail_two_two":            {want: false, input: "ruby-2.2"},
		"fail_three_twowo":        {want: false, input: "ruby-3.22"},
		"fail_threethree_two":     {want: false, input: "ruby-33.2"},
		"fail_two_two_dev":        {want: false, input: "ruby-2.2-dev"},
		"fail_three_twowo_dev":    {want: false, input: "ruby-3.22-dev"},
		"fail_threethree_two_dev": {want: false, input: "ruby-33.2-dev"},
	}

	o := Options{
		RubyVersion: "3.2",
	}

	for name, tc := range tests {
		testConfig.Environment.Contents.Packages[0] = tc.input
		got := o.isRubyPackage(testConfig)
		assert.Equalf(t, tc.want, got, "%s wanted: %s got: %s", name, tc.want, got)
	}
}

func TestParseRepo(t *testing.T) {
	testConfig := melange.Packages{
		Config: config.Configuration{
			Pipeline: []config.Pipeline{
				{
					// intentionally empty, overwrite for each test
				},
			},
		},
	}

	uri := "https://github.com/brianmario/charlock_holmes/archive/refs/tags/v${{package.version}}.tar.gz"
	repository := "https://github.com/brianmario/charlock_holmes.git"
	tests := map[string]struct {
		want string
		uses string
		with map[string]string
	}{
		"fetch_uri":     {want: uri, uses: "fetch", with: map[string]string{"uri": uri}},
		"checkout_repo": {want: repository, uses: "git-checkout", with: map[string]string{"repository": repository}},
		"other_junk":    {want: "", uses: "something-else", with: map[string]string{"junk": ""}},
	}

	for name, tc := range tests {
		testConfig.Config.Pipeline[0] = config.Pipeline{
			Uses: tc.uses,
			With: tc.with,
		}
		got := parseRepo(&testConfig)
		assert.Equalf(t, tc.want, got, "%s wanted: %s got %s", name, tc.want, got)
	}
}

func TestParseRef(t *testing.T) {
	pkgVersion := "0.0.0"
	testConfig := melange.Packages{
		Config: config.Configuration{
			Package: config.Package{
				Version: pkgVersion,
			},
			Pipeline: []config.Pipeline{
				{
					// intentionally empty, overwrite for each test
				},
			},
		},
	}

	tests := map[string]struct {
		want string
		uses string
		with map[string]string
	}{
		"fetch_uri":       {want: "v" + pkgVersion, uses: "fetch", with: map[string]string{"uri": "https://github.com/brianmario/charlock_holmes/archive/refs/tags/v${{package.version}}.tar.gz"}},
		"checkout_tag":    {want: "v" + pkgVersion, uses: "git-checkout", with: map[string]string{"tag": "v${{package.version}}"}},
		"checkout_branch": {want: "v" + pkgVersion, uses: "git-checkout", with: map[string]string{"branch": "v${{package.version}}"}},
		"checkout_junk":   {want: "", uses: "git-checkout", with: map[string]string{"junk": ""}},
		"other_junk":      {want: "", uses: "something-else", with: map[string]string{"junk": ""}},
	}

	for name, tc := range tests {
		testConfig.Config.Pipeline[0] = config.Pipeline{
			Uses: tc.uses,
			With: tc.with,
		}
		got := parseRef(&testConfig)
		assert.Equalf(t, tc.want, got, "%s wanted: %s got %s", name, tc.want, got)
	}
}
