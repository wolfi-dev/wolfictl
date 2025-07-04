package scan

import (
	"reflect"
	"sort"
	"testing"
)

func TestMergeRelatedFindings(t *testing.T) {
	tests := []struct {
		name     string
		input    []Finding
		expected []Finding
	}{
		{
			name: "merge CVE and GHSA findings for same package",
			input: []Finding{
				{
					Package: Package{
						ID:       "pkg1",
						Name:     "test-package",
						Version:  "1.0.0",
						Type:     "apk",
						Location: "/usr/lib/test.so",
						PURL:     "pkg:apk/test-package@1.0.0",
					},
					Vulnerability: Vulnerability{
						ID:           "CVE-2023-1234",
						Severity:     "high",
						Aliases:      []string{},
						FixedVersion: "1.0.1",
					},
				},
				{
					Package: Package{
						ID:       "pkg1",
						Name:     "test-package",
						Version:  "1.0.0",
						Type:     "apk",
						Location: "/usr/lib/test.so",
						PURL:     "pkg:apk/test-package@1.0.0",
					},
					Vulnerability: Vulnerability{
						ID:           "GHSA-xxxx-yyyy-zzzz",
						Severity:     "high",
						Aliases:      []string{"CVE-2023-1234"},
						FixedVersion: "1.0.1",
					},
				},
			},
			expected: []Finding{
				{
					Package: Package{
						ID:       "pkg1",
						Name:     "test-package",
						Version:  "1.0.0",
						Type:     "apk",
						Location: "/usr/lib/test.so",
						PURL:     "pkg:apk/test-package@1.0.0",
					},
					Vulnerability: Vulnerability{
						ID:           "GHSA-xxxx-yyyy-zzzz",
						Severity:     "high",
						Aliases:      []string{"CVE-2023-1234"},
						FixedVersion: "1.0.1",
					},
				},
			},
		},
		{
			name: "no merge for different packages",
			input: []Finding{
				{
					Package: Package{
						Name:     "package-a",
						Type:     "apk",
						Location: "/usr/lib/a.so",
					},
					Vulnerability: Vulnerability{
						ID:      "CVE-2023-1234",
						Aliases: []string{"GHSA-xxxx-yyyy-zzzz"},
					},
				},
				{
					Package: Package{
						Name:     "package-b",
						Type:     "apk",
						Location: "/usr/lib/b.so",
					},
					Vulnerability: Vulnerability{
						ID:      "GHSA-xxxx-yyyy-zzzz",
						Aliases: []string{"CVE-2023-1234"},
					},
				},
			},
			expected: []Finding{
				{
					Package: Package{
						Name:     "package-a",
						Type:     "apk",
						Location: "/usr/lib/a.so",
					},
					Vulnerability: Vulnerability{
						ID:      "CVE-2023-1234",
						Aliases: []string{"GHSA-xxxx-yyyy-zzzz"},
					},
				},
				{
					Package: Package{
						Name:     "package-b",
						Type:     "apk",
						Location: "/usr/lib/b.so",
					},
					Vulnerability: Vulnerability{
						ID:      "GHSA-xxxx-yyyy-zzzz",
						Aliases: []string{"CVE-2023-1234"},
					},
				},
			},
		},
		{
			name: "preserve all aliases in union",
			input: []Finding{
				{
					Package: Package{
						Name:     "test-package",
						Type:     "apk",
						Location: "/usr/lib/test.so",
					},
					Vulnerability: Vulnerability{
						ID:      "CVE-2023-1234",
						Aliases: []string{"GHSA-xxxx-yyyy-zzzz"},
					},
				},
				{
					Package: Package{
						Name:     "test-package",
						Type:     "apk",
						Location: "/usr/lib/test.so",
					},
					Vulnerability: Vulnerability{
						ID:      "GHSA-xxxx-yyyy-zzzz",
						Aliases: []string{"CVE-2023-1234", "GO-2023-5678"},
					},
				},
			},
			expected: []Finding{
				{
					Package: Package{
						Name:     "test-package",
						Type:     "apk",
						Location: "/usr/lib/test.so",
					},
					Vulnerability: Vulnerability{
						ID:      "GHSA-xxxx-yyyy-zzzz",
						Aliases: []string{"CVE-2023-1234", "GO-2023-5678"},
					},
				},
			},
		},
		{
			name: "three findings with transitive aliases",
			input: []Finding{
				{
					Package: Package{
						Name:     "test-package",
						Type:     "apk",
						Location: "/usr/lib/test.so",
					},
					Vulnerability: Vulnerability{
						ID:      "CVE-2023-1234",
						Aliases: []string{},
					},
				},
				{
					Package: Package{
						Name:     "test-package",
						Type:     "apk",
						Location: "/usr/lib/test.so",
					},
					Vulnerability: Vulnerability{
						ID:      "GHSA-xxxx-yyyy-zzzz",
						Aliases: []string{"CVE-2023-1234"},
					},
				},
				{
					Package: Package{
						Name:     "test-package",
						Type:     "apk",
						Location: "/usr/lib/test.so",
					},
					Vulnerability: Vulnerability{
						ID:      "GO-2023-5678",
						Aliases: []string{"GHSA-xxxx-yyyy-zzzz"},
					},
				},
			},
			expected: []Finding{
				{
					Package: Package{
						Name:     "test-package",
						Type:     "apk",
						Location: "/usr/lib/test.so",
					},
					Vulnerability: Vulnerability{
						ID:      "GHSA-xxxx-yyyy-zzzz",
						Aliases: []string{"CVE-2023-1234", "GO-2023-5678"},
					},
				},
			},
		},
		{
			name: "no merge for different locations",
			input: []Finding{
				{
					Package: Package{
						Name:     "test-package",
						Type:     "apk",
						Location: "/usr/lib/test.so",
					},
					Vulnerability: Vulnerability{
						ID:      "CVE-2023-1234",
						Aliases: []string{"GHSA-xxxx-yyyy-zzzz"},
					},
				},
				{
					Package: Package{
						Name:     "test-package",
						Type:     "apk",
						Location: "/usr/bin/test",
					},
					Vulnerability: Vulnerability{
						ID:      "GHSA-xxxx-yyyy-zzzz",
						Aliases: []string{"CVE-2023-1234"},
					},
				},
			},
			expected: []Finding{
				{
					Package: Package{
						Name:     "test-package",
						Type:     "apk",
						Location: "/usr/lib/test.so",
					},
					Vulnerability: Vulnerability{
						ID:      "CVE-2023-1234",
						Aliases: []string{"GHSA-xxxx-yyyy-zzzz"},
					},
				},
				{
					Package: Package{
						Name:     "test-package",
						Type:     "apk",
						Location: "/usr/bin/test",
					},
					Vulnerability: Vulnerability{
						ID:      "GHSA-xxxx-yyyy-zzzz",
						Aliases: []string{"CVE-2023-1234"},
					},
				},
			},
		},
		{
			name:     "handle empty findings list",
			input:    []Finding{},
			expected: []Finding{},
		},
		{
			name: "single finding unchanged",
			input: []Finding{
				{
					Package: Package{
						Name:     "test-package",
						Type:     "apk",
						Location: "/usr/lib/test.so",
					},
					Vulnerability: Vulnerability{
						ID:      "CVE-2023-1234",
						Aliases: []string{"GHSA-xxxx-yyyy-zzzz"},
					},
				},
			},
			expected: []Finding{
				{
					Package: Package{
						Name:     "test-package",
						Type:     "apk",
						Location: "/usr/lib/test.so",
					},
					Vulnerability: Vulnerability{
						ID:      "CVE-2023-1234",
						Aliases: []string{"GHSA-xxxx-yyyy-zzzz"},
					},
				},
			},
		},
		{
			name: "multiple unrelated vulnerabilities in same package",
			input: []Finding{
				{
					Package: Package{
						Name:     "test-package",
						Type:     "apk",
						Location: "/usr/lib/test.so",
					},
					Vulnerability: Vulnerability{
						ID:      "CVE-2023-1111",
						Aliases: []string{},
					},
				},
				{
					Package: Package{
						Name:     "test-package",
						Type:     "apk",
						Location: "/usr/lib/test.so",
					},
					Vulnerability: Vulnerability{
						ID:      "CVE-2023-2222",
						Aliases: []string{},
					},
				},
			},
			expected: []Finding{
				{
					Package: Package{
						Name:     "test-package",
						Type:     "apk",
						Location: "/usr/lib/test.so",
					},
					Vulnerability: Vulnerability{
						ID:      "CVE-2023-1111",
						Aliases: []string{},
					},
				},
				{
					Package: Package{
						Name:     "test-package",
						Type:     "apk",
						Location: "/usr/lib/test.so",
					},
					Vulnerability: Vulnerability{
						ID:      "CVE-2023-2222",
						Aliases: []string{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mergeRelatedFindings(tt.input)

			// Sort both slices for comparison
			sort.Sort(Findings(result))
			sort.Sort(Findings(tt.expected))

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("mergeRelatedFindings() = %#v, want %#v", result, tt.expected)
			}
		})
	}
}

func TestCreateAliasSet(t *testing.T) {
	tests := []struct {
		name     string
		finding  Finding
		expected map[string]struct{}
	}{
		{
			name: "finding with aliases",
			finding: Finding{
				Vulnerability: Vulnerability{
					ID:      "CVE-2023-1234",
					Aliases: []string{"GHSA-xxxx-yyyy-zzzz", "GO-2023-5678"},
				},
			},
			expected: map[string]struct{}{
				"CVE-2023-1234":       {},
				"GHSA-xxxx-yyyy-zzzz": {},
				"GO-2023-5678":        {},
			},
		},
		{
			name: "finding without aliases",
			finding: Finding{
				Vulnerability: Vulnerability{
					ID:      "CVE-2023-1234",
					Aliases: []string{},
				},
			},
			expected: map[string]struct{}{
				"CVE-2023-1234": {},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := createAliasSet(tt.finding)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("createAliasSet() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestFindingsAreRelated(t *testing.T) {
	tests := []struct {
		name     string
		f1       Finding
		f2       Finding
		expected bool
	}{
		{
			name: "related via direct ID match",
			f1: Finding{
				Vulnerability: Vulnerability{
					ID:      "CVE-2023-1234",
					Aliases: []string{"GHSA-xxxx-yyyy-zzzz"},
				},
			},
			f2: Finding{
				Vulnerability: Vulnerability{
					ID:      "GHSA-xxxx-yyyy-zzzz",
					Aliases: []string{"CVE-2023-1234"},
				},
			},
			expected: true,
		},
		{
			name: "related via alias overlap",
			f1: Finding{
				Vulnerability: Vulnerability{
					ID:      "CVE-2023-1234",
					Aliases: []string{},
				},
			},
			f2: Finding{
				Vulnerability: Vulnerability{
					ID:      "GHSA-xxxx-yyyy-zzzz",
					Aliases: []string{"CVE-2023-1234"},
				},
			},
			expected: true,
		},
		{
			name: "not related",
			f1: Finding{
				Vulnerability: Vulnerability{
					ID:      "CVE-2023-1111",
					Aliases: []string{},
				},
			},
			f2: Finding{
				Vulnerability: Vulnerability{
					ID:      "CVE-2023-2222",
					Aliases: []string{},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findingsAreRelated(tt.f1, tt.f2)
			if result != tt.expected {
				t.Errorf("findingsAreRelated() = %v, want %v", result, tt.expected)
			}
		})
	}
}
