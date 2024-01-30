package ruby

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionConstraints(t *testing.T) {
	tests := map[string]struct {
		input string
		check func(t assert.TestingT, err error, msg string, args ...interface{}) bool
	}{
		// success cases
		"pessimistic_minor":      {check: assert.NoErrorf, input: "spec.required_ruby_version = \"~> 3.3.0\""},
		"pessimistic_major":      {check: assert.NoErrorf, input: "spec.required_ruby_version = \"~> 3.2\""},
		"ge_double_quote":        {check: assert.NoErrorf, input: "spec.required_ruby_version = \">= 2.5.0\""},
		"ge_single_quote":        {check: assert.NoErrorf, input: "s.required_ruby_version = '>= 2.3.0'"},
		"two_constraints":        {check: assert.NoErrorf, input: "spec.required_ruby_version = '>= 2.6', '< 4'"},
		"requirement_new":        {check: assert.NoErrorf, input: "s.required_ruby_version = Gem::Requirement.new(\">= 2.4\")"},
		"requirement_new_freeze": {check: assert.NoErrorf, input: "s.required_ruby_version = Gem::Requirement.new(\">= 2.3\".freeze)"},
		"weird_spacing":          {check: assert.NoErrorf, input: "s.required_ruby_version     = \">= 2.7.0\""},
		"no_version":             {check: assert.NoErrorf, input: "no version specified should not fail either"},

		// failure cases
		"fail_pessimistic_minor": {check: assert.Errorf, input: "spec.required_ruby_version = \"~> 3.2.0\""},
		"fail_pessimistic_major": {check: assert.Errorf, input: "spec.required_ruby_version = \"~> 2.2\""},
		"fail_le_single":         {check: assert.Errorf, input: "s.required_ruby_version = '<= 2.3.0'"},
	}

	o := Options{
		RubyUpdateVersion: "3.3",
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Create a dummy gemspec file to read
			file, err := os.CreateTemp("", fmt.Sprintf("%s.gemspec", name))
			assert.NoError(t, err)
			defer os.Remove(file.Name())
			_, err = file.Write([]byte(tc.input))
			assert.NoError(t, err)

			// Check version constraints in gemspec
			err = o.checkVersionConstraint(file.Name())
			tc.check(t, err, "%s: %v", name, err)
		})
	}
}
