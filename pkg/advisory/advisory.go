package advisory

import (
	"sort"

	advisoryconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/advisory"
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
