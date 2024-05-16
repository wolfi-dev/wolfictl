package advisory

import (
	"reflect"

	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
)

// IndexDiffResult is the result of diffing two advisory document indexes.
type IndexDiffResult struct {
	Added   []v2.Document
	Removed []v2.Document

	Modified []DocumentDiffResult
}

// IsZero returns true there is no difference between the compared advisory
// document indexes.
func (r IndexDiffResult) IsZero() bool {
	return len(r.Added) == 0 && len(r.Removed) == 0 && len(r.Modified) == 0
}

// DocumentDiffResult is the result of diffing two advisory documents.
type DocumentDiffResult struct {
	Name string

	Added   v2.Advisories
	Removed v2.Advisories

	Modified []DiffResult
}

// IsZero returns true if there is no difference between the compared advisory
// documents.
func (r DocumentDiffResult) IsZero() bool {
	return len(r.Added) == 0 && len(r.Removed) == 0 && len(r.Modified) == 0
}

// DiffResult is the result of diffing two advisories.
type DiffResult struct {
	ID string

	Added   v2.Advisory
	Removed v2.Advisory

	AddedEvents   []v2.Event
	RemovedEvents []v2.Event
}

// IsZero returns true if there is no difference between the compared
// advisories.
func (r DiffResult) IsZero() bool {
	return r.Added.IsZero() && r.Removed.IsZero()
}

type EventDiffResult struct {
	ID string

	Added   v2.Event
	Removed v2.Event
}

// IndexDiff takes two advisory document indexes and returns a diff of the
// advisory data between them.
func IndexDiff(a, b *configs.Index[v2.Document]) IndexDiffResult {
	removed, added, common := venn(
		a.Select().Configurations(),
		b.Select().Configurations(),
		func(a, b v2.Document) bool {
			return a.Name() == b.Name()
		},
	)

	result := IndexDiffResult{
		Added:   added,
		Removed: removed,
	}

	for _, name := range documentNames(common) {
		diff := documentDiff(
			a.Select().WhereName(name).Configurations()[0],
			b.Select().WhereName(name).Configurations()[0],
		)
		if !diff.IsZero() {
			result.Modified = append(result.Modified, diff)
		}
	}

	return result
}

// documentDiff takes two advisory documents and returns a diff of their
// respective advisory lists.
func documentDiff(a, b v2.Document) DocumentDiffResult {
	removed, added, common := venn(
		a.Advisories,
		b.Advisories,
		func(a, b v2.Advisory) bool {
			return a.ID == b.ID
		},
	)

	result := DocumentDiffResult{
		Name:    a.Name(),
		Added:   added,
		Removed: removed,
	}

	for _, id := range advisoryIDs(common) {
		advA, _ := a.Advisories.Get(id, []string{})
		advB, _ := b.Advisories.Get(id, []string{})

		diff := advisoryDiff(advA, advB)
		if !diff.IsZero() {
			result.Modified = append(result.Modified, diff)
		}
	}

	return result
}

// advisoryDiff takes two advisories and if they are different, returns a DiffResult
// wrapping the two advisories; otherwise if they are the same, it returns a
// zero-value DiffResult.
func advisoryDiff(a, b v2.Advisory) DiffResult {
	if reflect.DeepEqual(a, b) {
		return DiffResult{}
	}

	if reflect.DeepEqual(a.SortedEvents(), b.SortedEvents()) {
		// No change with regard to events, so just return the advisories.
		return DiffResult{ID: a.ID, Added: b, Removed: a}
	}

	// Otherwise, we need to diff the events.

	removedEvents, addedEvents, _ := venn(
		a.SortedEvents(),
		b.SortedEvents(),
		func(a, b v2.Event) bool {
			return reflect.DeepEqual(a, b) // This means we won't diff the common events
		},
	)

	result := DiffResult{
		ID:            a.ID,
		Added:         b,
		Removed:       a,
		AddedEvents:   addedEvents,
		RemovedEvents: removedEvents,
	}

	return result
}

func documentNames(documents []v2.Document) []string {
	names := make([]string, len(documents))
	for i, document := range documents {
		names[i] = document.Name()
	}
	return names
}

func advisoryIDs(advisories []v2.Advisory) []string {
	ids := make([]string, len(advisories))
	for i, advisory := range advisories {
		ids[i] = advisory.ID
	}
	return ids
}

// venn takes two slices and returns three slices, the first containing the
// items found in the first slice but not the second, the second containing the
// items found in the second slice but not the first, and the third containing
// the items found in common between the two input slices (but the versions of
// the items from the first input slice in particular, since a given slice item
// can't represent both of the item's instances between the two input slices).
// venn also takes a function to compare two items for equality.
func venn[S interface{ ~[]T }, T any](s1, s2 S, equal func(a, b T) bool) (s1Only, s2Only, s1Common S) {
	for _, a := range s1 {
		found := false
		for _, b := range s2 {
			if equal(a, b) {
				found = true
				s1Common = append(s1Common, a)
				break
			}
		}

		if !found {
			s1Only = append(s1Only, a)
		}
	}

	for _, b := range s2 {
		found := false
		for _, a := range s1 {
			if equal(a, b) {
				found = true
				break
			}
		}

		if !found {
			s2Only = append(s2Only, b)
		}
	}

	return s1Only, s2Only, s1Common
}
