package scan

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"chainguard.dev/melange/pkg/config"
	"github.com/wolfi-dev/wolfictl/pkg/git"
	"golang.org/x/vuln/pkg/vulncheck"
)

func Sources(ctx context.Context, logger *slog.Logger, cfg *config.Configuration) ([]SourceResult, error) {
	// TODO: handle "fetch" pipelines

	const gitCheckoutPipelineName = "git-checkout"

	var targets []gitCloneTarget
	for i := range cfg.Pipeline {
		step := cfg.Pipeline[i]

		if step.Uses != gitCheckoutPipelineName {
			continue
		}

		// TODO: Ideally there's an elegant way to do this by leaning on Melange's code,
		//  but that code is pretty messy at the moment. I would've expected these
		//  substitutions that don't depend on runtime information to be done at parse
		//  time, but they're not.
		step.With["tag"] = strings.ReplaceAll(step.With["tag"], config.SubstitutionPackageVersion, cfg.Package.Version)

		t := gitCloneTarget{
			url: step.With["repository"],
			tag: step.With["tag"],
		}
		targets = append(targets, t)

		logger.Debug(
			"found git checkout step",
			"stepIndex",
			i,
			"repository",
			t.url,
			"tag",
			t.tag,
		)
	}

	logger.Debug("finished finding git checkout steps", "total", len(targets))

	var results []SourceResult
	for _, t := range targets {
		r, err := t.cloneAndRunGovulncheckSourceScan(ctx, logger)
		if err != nil {
			return nil, err
		}

		results = append(results, SourceResult{
			Name:            cfg.Name(),
			GitRepository:   t,
			VulncheckResult: r,
		})
	}

	return results, nil
}

type gitCloneTarget struct {
	url string
	tag string
}

func (t gitCloneTarget) cloneAndRunGovulncheckSourceScan(ctx context.Context, logger *slog.Logger) (*vulncheck.Result, error) {
	logger.Debug("beginning git clone", "url", t.url, "tag", t.tag)
	tempDir, err := git.TempCloneTag(t.url, t.tag, false)
	defer os.RemoveAll(tempDir)
	if err != nil {
		return nil, fmt.Errorf("unable to clone repo %q: %w", t.url, err)
	}
	logger.Debug("finished git clone", "url", t.url, "tag", t.tag)

	logger.Debug("beginning govulncheck source scan", "repo", t.url, "tag", t.tag, "tempDir", tempDir)
	result, err := runGovulncheckSource(ctx, tempDir)
	if err != nil {
		return nil, fmt.Errorf("unable to run govulncheck on %q: %w", t.url, err)
	}
	logger.Debug("finished govulncheck source scan", "target", t)

	return result, nil
}

// SourceResult is the result of scanning a package's source code for
// vulnerabilities using govulncheck.
type SourceResult struct {
	// The Name of the package described in the Melange configuration.
	Name string

	// GitRepository describes the repository that was scanned.
	GitRepository gitCloneTarget

	// VulncheckResult is the result of running govulncheck on the repository.
	VulncheckResult *vulncheck.Result
}

// String returns a human-readable representation of the result.
func (r SourceResult) String() string {
	s := fmt.Sprintf(
		"%s %s %s\n",
		r.Name,
		r.GitRepository.url,
		r.GitRepository.tag,
	)

	if len(r.VulncheckResult.Vulns) == 0 {
		s += "  No vulnerabilities found\n"
		return s
	}

	for _, v := range r.VulncheckResult.Vulns {
		s += fmt.Sprintf(
			"  %s %s %s\n",
			v.OSV.ID,
			v.ImportSink.String(),
			v.Symbol,
		)
	}

	return s
}
