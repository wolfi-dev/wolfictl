package ruby

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionConstraints(t *testing.T) {
	versionStrings := []string{
		"spec.required_ruby_version = \"~> 3.3.0\"",
		"spec.required_ruby_version = \"~> 3.2\"",
		"spec.required_ruby_version = \">= 2.5.0\"",
		"s.required_ruby_version = '>= 2.3.0'",
		"spec.required_ruby_version = '>= 2.6', '< 4'",
		"s.required_ruby_version = Gem::Requirement.new(\">= 2.4\")",
		"s.required_ruby_version = Gem::Requirement.new(\">= 2.3\".freeze)",
		"s.required_ruby_version     = \">= 2.7.0\"",
        "no version specified should not fail either",
	}

    o := RubyOptions{
        RubyUpdateVersion: "3.3",
    }

	for i, vs := range versionStrings {
		file, err := os.CreateTemp("", fmt.Sprintf("%d.gemspec", i))
		assert.NoError(t, err)
		defer os.Remove(file.Name())
		_, err = file.Write([]byte(vs))
        err = o.checkVersionConstraint(file.Name())
        assert.NoErrorf(t, err, "%v: %s", err, vs)
	}

	failVersionStrings := []string{
		"spec.required_ruby_version = \"~> 3.2.0\"",
		"spec.required_ruby_version = \"~> 2.2\"",
		"s.required_ruby_version = '<= 2.3.0'",
    }
	for i, vs := range failVersionStrings {
		file, err := os.CreateTemp("", fmt.Sprintf("%d.gemspec", i))
		assert.NoError(t, err)
		defer os.Remove(file.Name())
		_, err = file.Write([]byte(vs))
        err = o.checkVersionConstraint(file.Name())
        assert.Errorf(t, err, "%v: %s", err, vs)
	}
}
