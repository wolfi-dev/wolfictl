package advisory

import (
	"context"

	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
)

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
