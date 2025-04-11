package advisory

import (
	"context"

	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
)

// Store abstracts the storage and retrieval of advisory data.
type Store interface {
	Getter
	Putter
}

// Getter is the interface for retrieving advisory data.
type Getter interface {
	// PackageNames returns the list of package names that have advisories. The
	// order of the results is not guaranteed.
	PackageNames(ctx context.Context) ([]string, error)

	// Advisories returns the advisories for the given package name. If no error is
	// returned, it is guaranteed that all elements of the result slice contain
	// valid, non-empty data.
	Advisories(ctx context.Context, packageName string) ([]v2.PackageAdvisory, error)
}

// Putter is the interface for storing advisory data.
type Putter interface {
	// Upsert stores the advisory data from the given Request. Upsert creates a new
	// advisory or updates an existing advisory, depending on whether an advisory
	// already exists that matches the given Request.
	//
	// An existing advisory is considered to match the given Request if the named
	// package in the Request matches the package name in the advisory, and the
	// advisory ID or any of the aliases in the Request match the advisory ID or
	// aliases in the advisory, respectively. If the Request specified both an
	// advisory ID, the advisory referenced by the advisory ID must match the
	// package name in the Request, or an error should be returned.
	//
	// If the advisory ID in the Request is specified, only updating an existing
	// advisory (not creating a new advisory) is permitted.
	//
	// When updating an advisory, the updated set of aliases for the advisory is the
	// union of the existing aliases and the aliases in the Request.
	//
	// If the event specified in the Request is not zero (as determined by the
	// evaluation of the event's IsZero method), it is added to the advisory.
	//
	// If the advisory is unable to be created or updated because of the above rules
	// or because of an error encountered by the underlying implementation, an empty
	// string and the error are returned.
	//
	// Otherwise, the advisory ID for the newly created or updated advisory is
	// returned.
	Upsert(ctx context.Context, request Request) (string, error)
}

// MapByVulnID maps the given advisories by their vulnerability ID, creating a
// pre-indexed collection of advisories for performant lookup. The map keys are
// the vulnerability IDs, and the values are pointers to the corresponding
// PackageAdvisory structs.
func MapByVulnID(advisories []v2.PackageAdvisory) map[string]*v2.PackageAdvisory {
	advsByAlias := make(map[string]*v2.PackageAdvisory, len(advisories)) // even though we'll exceed this capacity if there are multiple aliases.

	for _, adv := range advisories {
		for _, alias := range adv.Aliases {
			advsByAlias[alias] = &adv
		}
	}

	return advsByAlias
}
