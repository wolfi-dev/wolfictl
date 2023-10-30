package scan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"slices"

	"github.com/anchore/syft/syft/pkg"
	"golang.org/x/vuln/pkg/vulncheck"
)

const TriageSourceGovulncheck = "govulncheck"

// Triage inspects an existing scan Result and attempts to triage each finding,
// returning a copy of the Result's list of findings, modified to include
// TriageAssessments where applicable.
func Triage(ctx context.Context, result Result, apkFile io.ReadSeeker) ([]Finding, error) {
	findings := slices.Clone(result.Findings)

	// Get the list of findings that are matched against a module in a Go binary,
	// and for each finding, also get the Go binary's name, so we can send the Go
	// binary to govulncheck for scanning.

	locationsForGovulncheck := make(map[string]*vulncheck.Result)

	for i := range result.Findings {
		f := result.Findings[i]
		if f.Package.Type != string(pkg.GoModulePkg) {
			continue
		}

		l := f.Package.Location
		if l == "" {
			return nil, fmt.Errorf("package %q location should not be empty", f.Package.Name)
		}

		// Add a sentinel value that will be replaced with the govulncheck result, to
		// signal that these location in the APK needs to be scanned by govulncheck.
		locationsForGovulncheck[l] = &vulncheck.Result{}
	}

	_, err := apkFile.Seek(0, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("failed to seek to start of APK file: %w", err)
	}

	gr, err := gzip.NewReader(apkFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader for APK file: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read next tar header: %w", err)
		}

		if _, ok := locationsForGovulncheck["/"+hdr.Name]; ok {
			by, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
			if err != nil {
				return nil, fmt.Errorf("failed to read tar entry %q: %w", hdr.Name, err)
			}

			r := bytes.NewReader(by)
			result, err := runGovulncheck(ctx, r)
			if err != nil {
				return nil, err
			}

			locationsForGovulncheck["/"+hdr.Name] = result
		}
	}

	govulnDBIndex, err := BuildIndexForGoVulnDB(ctx)
	if err != nil {
		return nil, err
	}

	// Now go back through findings and leverage the govulncheck results.
	for i := range findings {
		f := findings[i]
		if f.Package.Type != string(pkg.GoModulePkg) {
			continue
		}

		l := f.Package.Location
		if l == "" {
			return nil, fmt.Errorf("package %q location cannot be empty", f.Package.Name)
		}

		result := locationsForGovulncheck[l]
		if result == nil {
			return nil, fmt.Errorf("missing expected govulncheck result for location %q", l)
		}

		foundByGovulncheck := false
		for _, vuln := range result.Vulns {
			gvAliases := vuln.OSV.Aliases
			for _, alias := range gvAliases {
				if !slices.Contains(append(f.Vulnerability.Aliases, f.Vulnerability.ID), alias) {
					// This govulncheck result vuln alias is not relevant to this finding.
					continue
				}

				foundByGovulncheck = true

				assessment := TriageAssessment{
					Source:       TriageSourceGovulncheck,
					TruePositive: true,
					Reason: fmt.Sprintf(
						"affected symbol %q is present in Go binary (see %s)",
						vuln.Symbol,
						vuln.OSV.ID,
					),
				}
				findings[i].TriageAssessments = append(findings[i].TriageAssessments, assessment)

				// Other aliases might provide the same confirmation, but that would be
				// redundant, so we can stop here.
				break
			}
		}

		if !foundByGovulncheck {
			// If govulncheck didn't confirm the finding, but it did know what to look for
			// (that is, the vulnerability exists in Go's vulndb), then we can assume it's a
			// false positive. Otherwise, we can't make any assumptions, because govulncheck
			// didn't even consider the vulnerability.
			if !isKnownToGoVulnDB(f.Vulnerability, govulnDBIndex) {
				continue
			}

			assessment := TriageAssessment{
				Source:       TriageSourceGovulncheck,
				TruePositive: false,
				Reason: fmt.Sprintf(
					"no known affected symbols present in Go binary (see %s)",
					f.Vulnerability.ID,
				),
			}
			findings[i].TriageAssessments = append(findings[i].TriageAssessments, assessment)
		}
	}

	return findings, nil
}

func isKnownToGoVulnDB(v Vulnerability, govulnDBIndex *GoVulnDBIndex) bool {
	_, ok := govulnDBIndex.Get(v.ID)
	if ok {
		return true
	}

	for _, alias := range v.Aliases {
		_, ok := govulnDBIndex.Get(alias)
		if ok {
			return true
		}
	}

	return false
}
