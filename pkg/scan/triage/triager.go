package triage

import (
	"context"
	"errors"
	"io/fs"

	"github.com/chainguard-dev/clog"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/scan"
)

// Triager is the interface that wraps the Triage method.
type Triager interface {
	// Triage takes a scan result and returns a triage conclusion.
	//
	// It is expected that the implementation will account for all cases of a given
	// vulnerability in the scan result before returning an advisory request for the
	// vulnerability, such that the returned request can be considered ready to
	// apply to an advisory data set.
	//
	// Triage implementations can indicate that they did not reach a conclusion by
	// returning a nil request. Optionally, they can additionally return
	// ErrNoConclusion, which allows more information to be passed to the caller via
	// error-wrapping.
	Triage(ctx context.Context, vulnFindings scan.VulnFindings) (*advisory.Request, error)
}

// Do handles triaging of an APK's scan.Result by running the given triagers,
// using the triagers sequentially until one returns a non-nil request. Do
// returns a slice of advisory requests, each of which represents a triage
// conclusion for a unique vulnerability in the package.
func Do(ctx context.Context, triagers []Triager, result *scan.Result) ([]advisory.Request, error) {
	logger := clog.FromContext(ctx)
	logger.Info("begin triaging", "targetAPK", result.TargetAPK, "triagerCount", len(triagers), "findingCount", len(result.Findings))

	var requests []advisory.Request

	vulnFindings := result.ByVuln().Split()

	for _, vf := range vulnFindings {
		for _, triager := range triagers {
			req, err := triager.Triage(ctx, vf)
			if err != nil {
				if errors.Is(err, ErrNoConclusion) {
					continue
				}
				return nil, err
			}

			if req != nil {
				requests = append(requests, *req)
				break
			}
		}
	}

	return requests, nil
}

type APKOpener interface {
	// Open returns the APK file associated with the given distro package scan
	// target. The specified package can be either an origin package or a
	// subpackage. The caller is responsible for closing the returned file.
	Open(target scan.TargetAPK) (fs.File, error)

	// TODO: This interface would perhaps be a better fit in the scan package.
}
