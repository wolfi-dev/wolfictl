package nvdapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wolfi-dev/wolfictl/pkg/vuln"
)

func TestDetector_VulnerabilitiesForPackages(t *testing.T) {
	cases := []struct {
		pkg          string
		expectedCVEs []string
	}{
		{
			pkg:          "brotli",
			expectedCVEs: []string{"CVE-2020-8927"},
		},
		{
			pkg:          "libbpf",
			expectedCVEs: []string{"CVE-2021-45940", "CVE-2021-45941"},
		},
		{
			pkg:          "libev",
			expectedCVEs: []string{},
		},
	}

	for _, tt := range cases {
		t.Run(tt.pkg, func(t *testing.T) {
			// "Arrange"

			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				f, err := os.Open(fmt.Sprintf("testdata/%s.json", tt.pkg))
				require.NoError(t, err)

				_, err = io.Copy(w, f)
				require.NoError(t, err)
			}))
			defer ts.Close()

			parsedURL, err := url.Parse(ts.URL)
			require.NoError(t, err)
			host := parsedURL.Host

			detector := NewDetector(ts.Client(), host, "some-api-key")

			// "Act"

			vulns, err := detector.VulnerabilitiesForPackages(context.Background(), tt.pkg)
			require.NoError(t, err)

			// "Assert"

			// We should have matches for exactly one package (based on the way this test is set up).
			require.Len(t, vulns, 1)

			resultVulnMatches := vulns[tt.pkg]
			resultCVEs := lo.Map(resultVulnMatches, vulnMatchToCVE)
			assert.ElementsMatch(t, tt.expectedCVEs, resultCVEs)
		})
	}
}

//nolint:gocritic // hugeParam
func vulnMatchToCVE(vuln vuln.Match, _ int) string {
	return vuln.Vulnerability.ID
}
