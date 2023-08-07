package advisory

import (
	"sort"

	"github.com/openvex/go-vex/pkg/vex"
	advisoryconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/versions"
)

// Latest returns the latest entry among the given set of entries for an
// advisory. If there are no entries, Latest returns nil.
func Latest(entries []advisoryconfigs.Entry) *advisoryconfigs.Entry {
	if len(entries) == 0 {
		return nil
	}

	// Try to respect the caller's sort order, and make changes only in this scope.
	items := make([]advisoryconfigs.Entry, len(entries))
	copy(items, entries)

	sort.SliceStable(items, func(i, j int) bool {
		return items[i].Timestamp.Before(items[j].Timestamp)
	})

	latestEntry := items[len(items)-1]
	return &latestEntry
}

// IsResolved returns true if the latest entry for an advisory indicates that
// the vulnerability is resolved for the given package. If the currentAPKVersion
// parameter is provided, this function checks to see if the advisory can be
// considered resolved for the given package version.
func IsResolved(advisory []advisoryconfigs.Entry, currentAPKVersion string) bool {
	latestEntry := Latest(advisory)

	if latestEntry == nil {
		return false
	}

	if latestEntry.Status == vex.StatusNotAffected {
		return true
	}

	if currentAPKVersion == "" {
		return false
	}

	fixedVersion, err := versions.NewVersion(latestEntry.FixedVersion)
	if err != nil {
		return false
	}
	currentVersion, err := versions.NewVersion(currentAPKVersion)
	if err != nil {
		return false
	}

	if currentVersion.GreaterThanOrEqual(fixedVersion) {
		return true
	}

	return false
}
