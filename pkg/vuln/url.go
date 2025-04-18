package vuln

import (
	"fmt"

	vulnadvs "github.com/chainguard-dev/advisory-schema/pkg/vuln"
)

// URL returns the canonical web URL for the given vulnerability ID.
func URL(id string) string {
	switch {
	case vulnadvs.RegexCVE.MatchString(id):
		return fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", id)

	case vulnadvs.RegexGHSA.MatchString(id):
		return fmt.Sprintf("https://github.com/advisories/%s", id)
	}

	return ""
}
