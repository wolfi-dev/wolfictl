package advisory

import (
	"context"
	"errors"

	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
)

// ErrNoAdvisories is returned by Getter implementations when there is no
// advisory data available for the requested package. If a more serious error
// with data access occurs (e.g. a permissions issue), a different error should
// be returned.
//
// It is not required for implementations to return this error when returning a
// zero-length slice of advisory data: this is merely a sentinel error to signal
// to the caller that the rest of the error chain represents a normal "no data"
// condition.
var ErrNoAdvisories = errors.New("no advisories found")

// Store abstracts the storage and retrieval of advisory data.
type Store interface {
	Getter

	// TODO: write-oriented interface
}

// Getter is the interface for retrieving advisory data.
type Getter interface {
	// PackageNames returns the list of package names that have advisories.
	PackageNames(ctx context.Context) ([]string, error)

	// Advisories returns the advisories for the given package name.
	Advisories(ctx context.Context, packageName string) ([]v2.PackageAdvisory, error)
}
