package vuln

import (
	"context"
)

type Detector interface {
	VulnerabilitiesForPackages(context.Context, ...string) (map[string][]Match, error)
	VulnerabilitiesForPackage(context.Context, string) ([]Match, error)
}
