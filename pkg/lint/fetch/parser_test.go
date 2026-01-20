package fetch

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// Helper functions for testing
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func equalGitRefSlices(a, b []gitRefInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func TestFindYamlValue(t *testing.T) {
	yamlData := `
key1: value1
key2: value2
nested:
  subkey: subvalue
`
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(yamlData), &root); err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	mapping := root.Content[0]

	// Test existing key
	value := findYamlValue(mapping, "key1")
	if value == nil || value.Value != "value1" {
		t.Errorf("Expected to find 'value1', got %v", value)
	}

	// Test non-existing key
	value = findYamlValue(mapping, "nonexistent")
	if value != nil {
		t.Errorf("Expected nil for non-existent key, got %v", value)
	}

	// Test nested key
	nested := findYamlValue(mapping, "nested")
	if nested == nil {
		t.Fatalf("Expected to find nested mapping")
	}
	subvalue := findYamlValue(nested, "subkey")
	if subvalue == nil || subvalue.Value != "subvalue" {
		t.Errorf("Expected to find 'subvalue', got %v", subvalue)
	}
}

func TestGetYamlString(t *testing.T) {
	yamlData := `
stringkey: "string value"
intkey: 42
nested:
  subkey: "nested value"
`
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(yamlData), &root); err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	mapping := root.Content[0]

	// Test string value
	result := getYamlString(mapping, "stringkey")
	if result != "string value" {
		t.Errorf("Expected 'string value', got %q", result)
	}

	// Test non-string value
	result = getYamlString(mapping, "intkey")
	if result != "42" {
		t.Errorf("Expected '42', got %q", result)
	}

	// Test non-existent key
	result = getYamlString(mapping, "nonexistent")
	if result != "" {
		t.Errorf("Expected empty string for non-existent key, got %q", result)
	}
}

func TestProcessPipelineSteps(t *testing.T) {
	yamlData := `
- uses: fetch
  with:
    uri: https://example.com/test-1.0.0.tar.gz
- uses: git-checkout
  with:
    repository: https://github.com/example/test
    tag: v1.0.0
- uses: git-checkout
  with:
    repository: https://github.com/example/test
    branch: main
- uses: git-checkout
  with:
    repository: https://github.com/example/test
    ref: def456
- uses: run
  runs: echo "not a source step"
- uses: fetch
  with:
    uri: https://example.com/another-file.tar.gz
- uses: step
  with:
    pipeline:
      - uses: fetch
        with:
          uri: https://example.com/nested-fetch.tar.gz
`

	var pipeline yaml.Node
	if err := yaml.Unmarshal([]byte(yamlData), &pipeline); err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	sources := sourceData{}
	// The unmarshaled node might be a DocumentNode, need to get the content
	pipelineNode := &pipeline
	if pipeline.Kind == yaml.DocumentNode && len(pipeline.Content) > 0 {
		pipelineNode = pipeline.Content[0]
	}
	processPipelineSteps(pipelineNode, &sources)

	expectedFetchURLs := []string{
		"https://example.com/test-1.0.0.tar.gz",
		"https://example.com/another-file.tar.gz",
		"https://example.com/nested-fetch.tar.gz",
	}
	if !equalStringSlices(sources.fetchURLs, expectedFetchURLs) {
		t.Errorf("fetchURLs: expected %v, got %v", expectedFetchURLs, sources.fetchURLs)
	}

	expectedGitTags := []string{"v1.0.0"}
	if !equalStringSlices(sources.gitTags, expectedGitTags) {
		t.Errorf("gitTags: expected %v, got %v", expectedGitTags, sources.gitTags)
	}

	expectedGitBranches := []gitRefInfo{
		{Ref: "def456"},
	}
	if !equalGitRefSlices(sources.gitBranches, expectedGitBranches) {
		t.Errorf("gitBranches: expected %v, got %v", expectedGitBranches, sources.gitBranches)
	}
}

func TestExtractRawPipelineDataEmpty(t *testing.T) {
	tests := []struct {
		name     string
		yamlData string
	}{
		{"nil_root", ""},
		{"empty_document", "{}"},
		{"no_pipeline", `package: {name: test, version: 1.0.0}`},
		{"empty_pipeline", `pipeline: []`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var root *yaml.Node
			if tt.yamlData != "" {
				var node yaml.Node
				if err := yaml.Unmarshal([]byte(tt.yamlData), &node); err != nil {
					t.Fatalf("Failed to parse YAML: %v", err)
				}
				root = &node
			}

			sources := extractRawPipelineData(root)
			if !sources.isEmpty() {
				t.Errorf("Expected empty sources, got %+v", sources)
			}
		})
	}
}

func TestExtractRawPipelineDataComplexNesting(t *testing.T) {
	yamlData := `
package:
  name: test
  version: 1.0.0
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/main.tar.gz
  - uses: step
    with:
      pipeline:
        - uses: git-checkout
          with:
            repository: https://github.com/example/nested
            tag: v2.0.0
        - uses: step
          with:
            pipeline:
              - uses: fetch
                with:
                  uri: https://example.com/deeply-nested.tar.gz
subpackages:
  - name: sub1
    pipeline:
      - uses: fetch
        with:
          uri: https://example.com/sub1.tar.gz
  - name: sub2
    pipeline:
      - uses: git-checkout
        with:
          repository: https://github.com/example/sub2
          tag: v3.0.0
`

	var root yaml.Node
	if err := yaml.Unmarshal([]byte(yamlData), &root); err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	sources := extractRawPipelineData(&root)

	expectedFetchURLs := []string{
		"https://example.com/main.tar.gz",
		"https://example.com/deeply-nested.tar.gz",
		"https://example.com/sub1.tar.gz",
	}
	if !equalStringSlices(sources.fetchURLs, expectedFetchURLs) {
		t.Errorf("fetchURLs: expected %v, got %v", expectedFetchURLs, sources.fetchURLs)
	}

	expectedGitTags := []string{"v2.0.0", "v3.0.0"}
	if !equalStringSlices(sources.gitTags, expectedGitTags) {
		t.Errorf("gitTags: expected %v, got %v", expectedGitTags, sources.gitTags)
	}
}
