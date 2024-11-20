package vulnid

import (
	"fmt"
	"strings"

	"github.com/savioxavier/termlink"
)

var termSupportsHyperlinks = termlink.SupportsHyperlinks()

func Hyperlink(id string) string {
	if !termSupportsHyperlinks {
		return id
	}

	switch {
	case strings.HasPrefix(id, "CVE-"):
		return termlink.Link(id, fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", id))

	case strings.HasPrefix(id, "GHSA-"):
		return termlink.Link(id, fmt.Sprintf("https://github.com/advisories/%s", id))

	case strings.HasPrefix(id, "CGA-"):
		return termlink.Link(id, fmt.Sprintf("https://images.chainguard.dev/security/%s", id))
	}

	return id
}
