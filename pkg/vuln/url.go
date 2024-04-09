package vuln

import "fmt"

// URL returns the canonical web URL for the given vulnerability ID.
func URL(id string) string {
	switch {
	case RegexCVE.MatchString(id):
		return fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", id)

	case RegexGHSA.MatchString(id):
		return fmt.Sprintf("https://github.com/advisories/%s", id)
	}

	return ""
}
