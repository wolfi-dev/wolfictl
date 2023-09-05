package vuln

import (
	"fmt"
	"regexp"
)

var (
	RegexCVE  = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	RegexGHSA = regexp.MustCompile(`^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)
	RegexGO   = regexp.MustCompile(`^GO-\d{4}-\d{4}$`)
)

// ValidateID returns an error if the given ID is not a valid CVE ID, GHSA ID,
// or Go vulnerability ID.
func ValidateID(id string) error {
	if !RegexCVE.MatchString(id) && !RegexGHSA.MatchString(id) && !RegexGO.MatchString(id) {
		return fmt.Errorf("%q is not a valid CVE ID, GHSA ID, or Go vulnerability ID", id)
	}

	return nil
}
