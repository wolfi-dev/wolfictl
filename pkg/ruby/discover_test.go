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
	o := RubyOptions{
		RubyVersion: "3.2",
	}

	shouldBeTrue := []string{
		"ruby-3.2",
		"ruby-3.2-dev",
	}
	for _, pkg := range shouldBeTrue {
		testConfig.Environment.Contents.Packages[0] = pkg
		assert.Truef(t, o.isRubyPackage(testConfig), "%s should be true", pkg)
	}

	shouldBeFalse := []string{
		"ruby-2.2",
		"ruby-3.22",
		"ruby-33.2",
		"ruby-2.2-dev",
		"ruby-3.22-dev",
		"ruby-33.2-dev",
	}
	for _, pkg := range shouldBeFalse {
		testConfig.Environment.Contents.Packages[0] = pkg
		assert.Falsef(t, o.isRubyPackage(testConfig), "%s should be false", pkg)
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
	testConfig.Config.Pipeline[0] = config.Pipeline{
		Uses: "fetch",
		With: map[string]string{
			"uri": uri,
		},
	}
	assert.Equal(t, uri, parseRepo(&testConfig))

	repository := "https://github.com/brianmario/charlock_holmes.git"
	testConfig.Config.Pipeline[0] = config.Pipeline{
		Uses: "git-checkout",
		With: map[string]string{
			"repository": repository,
		},
	}
	assert.Equal(t, repository, parseRepo(&testConfig))

	testConfig.Config.Pipeline[0] = config.Pipeline{
		Uses: "something-else",
		With: map[string]string{
			"junk": "",
		},
	}
	assert.Equal(t, "", parseRepo(&testConfig))
}

func TestParseRef(t *testing.T) {
	testConfig := melange.Packages{
		Config: config.Configuration{
			Package: config.Package{
				Version: "0.0.0",
			},
			Pipeline: []config.Pipeline{
				{
					// intentionally empty, overwrite for each test
				},
			},
		},
	}
	want := "v0.0.0"

	uri := "https://github.com/brianmario/charlock_holmes/archive/refs/tags/v${{package.version}}.tar.gz"
	testConfig.Config.Pipeline[0] = config.Pipeline{
		Uses: "fetch",
		With: map[string]string{
			"uri": uri,
		},
	}
	assert.Equal(t, want, parseRef(&testConfig))

	tag := "v${{package.version}}"
	testConfig.Config.Pipeline[0] = config.Pipeline{
		Uses: "git-checkout",
		With: map[string]string{
			"tag": tag,
		},
	}
	assert.Equal(t, want, parseRef(&testConfig))

	branch := "v${{package.version}}"
	testConfig.Config.Pipeline[0] = config.Pipeline{
		Uses: "git-checkout",
		With: map[string]string{
			"branch": branch,
		},
	}
	assert.Equal(t, want, parseRef(&testConfig))

	testConfig.Config.Pipeline[0] = config.Pipeline{
		Uses: "git-checkout",
		With: map[string]string{
			"junk": "",
		},
	}
	assert.Equal(t, "", parseRef(&testConfig))

	testConfig.Config.Pipeline[0] = config.Pipeline{
		Uses: "something-else",
		With: map[string]string{
			"junk": "",
		},
	}
	assert.Equal(t, "", parseRef(&testConfig))
}
