package advisory

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func TestCompleteAliasSet(t *testing.T) {
	ctx := t.Context()

	af := mockAliasFinder{
		cveByGHSA: map[string]string{
			"GHSA-2222-2222-2222": "CVE-2222-2222",
			"GHSA-3333-3333-3333": "CVE-3333-3333",
			"GHSA-3r3r-3r3r-3r3r": "CVE-3333-3333",
		},
		ghsasByCVE: map[string][]string{
			"CVE-2222-2222": {"GHSA-2222-2222-2222"},
			"CVE-3333-3333": {"GHSA-3333-3333-3333", "GHSA-3r3r-3r3r-3r3r"},
		},
	}

	cases := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "empty input",
			input:    nil,
			expected: nil,
		},
		{
			name: "single id, already complete",
			input: []string{
				"GHSA-pppp-pppp-pppp",
			},
			expected: []string{
				"GHSA-pppp-pppp-pppp",
			},
		},
		{
			name: "single id, needs a CVE alias",
			input: []string{
				"GHSA-2222-2222-2222",
			},
			expected: []string{
				"CVE-2222-2222",
				"GHSA-2222-2222-2222",
			},
		},
		{
			name: "single id, needs a GHSA alias",
			input: []string{
				"CVE-2222-2222",
			},
			expected: []string{
				"CVE-2222-2222",
				"GHSA-2222-2222-2222",
			},
		},
		{
			name: "multiple in, and need to find aliases of aliases",
			input: []string{
				"GHSA-2222-2222-2222",
				"GHSA-3333-3333-3333", // i.e. first resolve to CVE-3333-3333, and from there to GHSA-3r3r-3r3r-3r3r
			},
			expected: []string{
				"CVE-2222-2222",
				"CVE-3333-3333",
				"GHSA-2222-2222-2222",
				"GHSA-3333-3333-3333",
				"GHSA-3r3r-3r3r-3r3r",
			},
		},
		{
			name: "multiple in, already complete",
			input: []string{
				"CVE-3333-3333",
				"GHSA-3333-3333-3333",
				"GHSA-3r3r-3r3r-3r3r",
			},
			expected: []string{
				"CVE-3333-3333",
				"GHSA-3333-3333-3333",
				"GHSA-3r3r-3r3r-3r3r",
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := CompleteAliasSet(ctx, af, tt.input)
			require.NoError(t, err)

			if diff := cmp.Diff(tt.expected, actual); diff != "" {
				t.Errorf("unexpected results (-want +got):\n%s", diff)
			}
		})
	}
}
