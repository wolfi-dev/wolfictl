package advisory

import (
	"sort"

	advisoryconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/event"
)

// Latest returns the latest event among the given set of events for an
// advisory. If there are no events, Latest returns nil.
func Latest(events []advisoryconfigs.Event) *advisoryconfigs.Event {
	if len(events) == 0 {
		return nil
	}

	// Try to respect the caller's sort order, and make changes only in this scope.
	items := make([]advisoryconfigs.Event, len(events))
	copy(items, events)

	sort.SliceStable(items, func(i, j int) bool {
		return items[i].Timestamp.Before(items[j].Timestamp)
	})

	latestEntry := items[len(items)-1]
	return &latestEntry
}
