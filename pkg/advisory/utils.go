package advisory

import v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"

// MapByVulnID maps the given advisories by their vulnerability ID, creating a
// pre-indexed collection of advisories for performant lookup. The map keys are
// the vulnerability IDs, and the values are pointers to the corresponding
// PackageAdvisory structs.
func MapByVulnID(advisories []v2.PackageAdvisory) map[string]*v2.PackageAdvisory {
	advsByAlias := make(map[string]*v2.PackageAdvisory, len(advisories)) // even though we'll exceed this capacity if there are multiple aliases.

	for _, adv := range advisories {
		advCopy := adv // Create a copy of the loop variable
		for _, alias := range adv.Aliases {
			advsByAlias[alias] = &advCopy
		}
	}

	return advsByAlias
}
