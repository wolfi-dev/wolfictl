package fetch

import "testing"

func TestBuildPackagePatterns(t *testing.T) {
	tests := []struct {
		name           string
		packageName    string
		packageVersion string
		testURL        string
		testTag        string
		expectURLMatch bool
		expectTagMatch bool
	}{
		{
			name:           "exact_version_match",
			packageName:    "test-package",
			packageVersion: "1.2.3",
			testURL:        "https://example.com/test-package-1.2.3.tar.gz",
			testTag:        "v1.2.3",
			expectURLMatch: true,
			expectTagMatch: true,
		},
		{
			name:           "version_in_path",
			packageName:    "test-package",
			packageVersion: "1.2.3",
			testURL:        "https://example.com/test-package/1.2.3/source.tar.gz",
			testTag:        "1.2.3",
			expectURLMatch: true,
			expectTagMatch: true,
		},
		{
			name:           "underscore_separator",
			packageName:    "test-package",
			packageVersion: "1.2.3",
			testURL:        "https://example.com/test-package_1.2.3.tar.gz",
			testTag:        "v1.2.3",
			expectURLMatch: true,
			expectTagMatch: true,
		},
		{
			name:           "match_different_version",
			packageName:    "test-package",
			packageVersion: "1.2.3",
			testURL:        "https://example.com/test-package-2.0.0.tar.gz",
			testTag:        "v2.0.0",
			expectURLMatch: true,  // anyVersionURL should match any version
			expectTagMatch: false, // exactVersionTag should NOT match different version
		},
		{
			name:           "no_match_different_package",
			packageName:    "test-package",
			packageVersion: "1.2.3",
			testURL:        "https://example.com/other-package-1.2.3.tar.gz",
			testTag:        "v1.2.3",
			expectURLMatch: false,
			expectTagMatch: true, // Tag should match version regardless of package name
		},
		{
			name:           "special_chars_in_name",
			packageName:    "test.package",
			packageVersion: "1.2.3",
			testURL:        "https://example.com/test.package-1.2.3.tar.gz",
			testTag:        "v1.2.3",
			expectURLMatch: true,
			expectTagMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patterns, err := buildPackagePatterns(tt.packageName, tt.packageVersion)
			if err != nil {
				t.Fatalf("buildPackagePatterns returned error: %v", err)
			}

			urlMatch := patterns.anyVersionURL.MatchString(tt.testURL)
			if urlMatch != tt.expectURLMatch {
				t.Errorf("URL match: expected %v, got %v for URL: %s", tt.expectURLMatch, urlMatch, tt.testURL)
			}

			tagMatch := patterns.exactVersionTag.MatchString(tt.testTag)
			if tagMatch != tt.expectTagMatch {
				t.Errorf("Tag match: expected %v, got %v for tag: %s", tt.expectTagMatch, tagMatch, tt.testTag)
			}
		})
	}
}

func TestBuildPackagePatternsNilInputs(t *testing.T) {
	tests := []struct {
		name           string
		packageName    string
		packageVersion string
	}{
		{"empty_name", "", "1.2.3"},
		{"empty_version", "test", ""},
		{"both_empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patterns, err := buildPackagePatterns(tt.packageName, tt.packageVersion)
			if err == nil {
				t.Errorf("Expected error for invalid inputs, got patterns: %v", patterns)
			}
			if patterns != nil {
				t.Errorf("Expected nil patterns for invalid inputs, got %v", patterns)
			}
		})
	}
}

func TestHasAnyTemplate(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"${{package.version}}", true},
		{"${{vars.custom}}", true},
		{"${{ package.version }}", true},
		{"no template here", false},
		{"${ not valid }", false},
		{"https://example.com/${{package.version}}/file.tar.gz", true},
		{"", false},
		{"${{package.version}} and ${{vars.other}}", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := hasAnyTemplate(tt.input)
			if result != tt.expected {
				t.Errorf("hasAnyTemplate(%q) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestHasVersionTemplate(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"${{package.version}}", true},
		{"${{package.full-version}}", true},
		{"${{vars.version}}", true},
		{"${{vars.my_version}}", true},
		{"${{vars.version_tag}}", true},
		{"${{package.name}}", false},
		{"${{vars.other}}", false},
		{"no template", false},
		{"${{package.version | replace: \".\", \"_\"}}", true},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := hasVersionTemplate(tt.input)
			if result != tt.expected {
				t.Errorf("hasVersionTemplate(%q) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}
