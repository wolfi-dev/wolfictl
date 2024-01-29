package ruby

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionConstraints(t *testing.T) {
	tests := map[string]struct {
		input       string
		shouldError bool
	}{
		// success cases
		"pessimistic_minor":      {shouldError: false, input: "spec.required_ruby_version = \"~> 3.3.0\""},
		"pessimistic_major":      {shouldError: false, input: "spec.required_ruby_version = \"~> 3.2\""},
		"ge_double_quote":        {shouldError: false, input: "spec.required_ruby_version = \">= 2.5.0\""},
		"ge_single_quote":        {shouldError: false, input: "s.required_ruby_version = '>= 2.3.0'"},
		"two_constraints":        {shouldError: false, input: "spec.required_ruby_version = '>= 2.6', '< 4'"},
		"requirement_new":        {shouldError: false, input: "s.required_ruby_version = Gem::Requirement.new(\">= 2.4\")"},
		"requirement_new_freeze": {shouldError: false, input: "s.required_ruby_version = Gem::Requirement.new(\">= 2.3\".freeze)"},
		"weird_spacing":          {shouldError: false, input: "s.required_ruby_version     = \">= 2.7.0\""},
		"no_version":             {shouldError: false, input: "no version specified should not fail either"},

		// failure cases
		"fail_pessimistic_minor": {shouldError: true, input: "spec.required_ruby_version = \"~> 3.2.0\""},
		"fail_pessimistic_major": {shouldError: true, input: "spec.required_ruby_version = \"~> 2.2\""},
		"fail_le_single":         {shouldError: true, input: "s.required_ruby_version = '<= 2.3.0'"},
	}

	o := Options{
		RubyUpdateVersion: "3.3",
	}

	for name, tc := range tests {
		// Create a dummy gemspec file to read
		file, err := os.CreateTemp("", fmt.Sprintf("%s.gemspec", name))
		assert.NoError(t, err)
		defer os.Remove(file.Name())
		_, err = file.Write([]byte(tc.input))
		assert.NoError(t, err)

		// Check version constraints in gemspec
		err = o.checkVersionConstraint(file.Name())
		if tc.shouldError {
			assert.Errorf(t, err, "%s: %v", name, err)
		} else {
			assert.NoErrorf(t, err, "%s: %v", name, err)
		}
	}
}
