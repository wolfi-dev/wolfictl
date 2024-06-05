package govulncheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/anchore/syft/syft/pkg"
	"github.com/chainguard-dev/clog"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/scan"
	"github.com/wolfi-dev/wolfictl/pkg/scan/triage"
	"go.opentelemetry.io/otel"
	"golang.org/x/vuln/pkg/client"
	"golang.org/x/vuln/pkg/govulncheck"
	vulnscan "golang.org/x/vuln/pkg/scan"
	"golang.org/x/vuln/pkg/vulncheck"
)

// Triager uses govulncheck to triage Go module vulnerabilities by inspecting
// the APK's Go binaries for affected symbols.
//
// For more information on the govulncheck project, see
// https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck.
type Triager struct {
	apkFS fs.FS

	datastore                *goVulnDBIndex
	datastoreGenerationMutex *sync.Mutex

	govulncheckResultCache map[string]*vulncheck.Result
}

// New creates a new Triager.
func New(apkFS fs.FS) *Triager {
	return &Triager{
		apkFS:                    apkFS,
		datastoreGenerationMutex: &sync.Mutex{},
		govulncheckResultCache:   make(map[string]*vulncheck.Result),
	}
}

type reason struct {
	location        string
	affectedSymbols []string
}

// Triage implements triage.Triager.
func (t *Triager) Triage(ctx context.Context, vfs scan.VulnFindings) (*advisory.Request, error) {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, fmt.Sprintf("govulncheck triage %s in %s", vfs.VulnerabilityID, vfs.TargetAPK.Name))
	defer span.End()

	logger := clog.FromContext(ctx)
	logger = logger.With("triager", "govulncheck")

	logger.Info("triaging", "vulnerabilityID", vfs.VulnerabilityID, "targetAPK", vfs.TargetAPK.Name)

	conclusions := make([]triage.Conclusion, len(vfs.Findings))

	for i := range vfs.Findings {
		finding := vfs.Findings[i]

		if finding.Package.Type != string(pkg.GoModulePkg) {
			return nil, fmt.Errorf("%s (at %s) is not a Go module: %w", finding.Package.Name, finding.Package.Location, triage.ErrNoConclusion)
		}

		vcResult, err := t.runGovulncheck(ctx, finding.Package)
		if err != nil {
			return nil, fmt.Errorf("running govulncheck on file in APK: %s: %w", finding.Package.Location, err)
		}

		if vcResult == nil {
			return nil, fmt.Errorf("nil result running govulncheck on file in APK: %s", finding.Package.Location)
		}

		govulnDBIndex, err := t.buildDatastoreForGoVulnDB(ctx)
		if err != nil {
			return nil, fmt.Errorf("building go vulnDB index: %w", err)
		}

		var affectedSymbolsFound []string
		for _, vuln := range vcResult.Vulns {
			gvAliases := vuln.OSV.Aliases
			for _, alias := range gvAliases {
				if !slices.Contains(append(finding.Vulnerability.Aliases, finding.Vulnerability.ID), alias) {
					// This govulncheck result vuln alias is not relevant to this finding.
					continue
				}

				affectedSymbolsFound = append(affectedSymbolsFound, vuln.Symbol)
			}
		}

		if len(affectedSymbolsFound) > 0 {
			// Deduplicate the affected symbols.
			slices.Sort(affectedSymbolsFound)
			affectedSymbolsFound = slices.Compact(affectedSymbolsFound)

			c := triage.Conclusion{
				Type: triage.TruePositive,
				Reason: reason{
					location:        finding.Package.Location,
					affectedSymbols: affectedSymbolsFound,
				},
			}
			conclusions[i] = c
			continue
		}

		// If govulncheck didn't confirm the finding, but it did know what to look for
		// (that is, the vulnerability exists in Go's vulndb), then we can assume it's a
		// false positive. Otherwise, we can't make any assumptions, because govulncheck
		// didn't even consider the vulnerability.
		if !govulnDBIndex.isKnownToGoVulnDB(finding.Vulnerability) {
			logger.Debug("vulnerability not in Go vulndb", "vulnerabilityID", finding.Vulnerability.ID, "component", finding.Package.Name, "location", finding.Package.Location)
			continue
		}

		c := triage.Conclusion{
			Type: triage.FalsePositive,
			Reason: reason{
				location: finding.Package.Location,
			},
		}
		conclusions[i] = c
	}

	event := eventFromConclusions(conclusions)

	if event == nil {
		logger.Info("no conclusion reached", "vulnerabilityID", vfs.VulnerabilityID)
		return nil, triage.ErrNoConclusion
	}

	logger.Info("conclusion reached", "vulnerabilityID", vfs.VulnerabilityID, "eventType", event.Type)

	return &advisory.Request{
		Package:         vfs.TargetAPK.OriginPackageName,
		VulnerabilityID: vfs.VulnerabilityID,
		Event:           *event,
	}, nil
}

func eventFromConclusions(conclusions []triage.Conclusion) *v2.Event {
	eventType := triage.EventTypeFromConclusions(conclusions)

	if eventType == "" {
		// No conclusion reached
		return nil
	}

	e := &v2.Event{
		Timestamp: v2.Now(),
		Type:      eventType,
	}

	if eventType == v2.EventTypeTruePositiveDetermination {
		e.Data = v2.TruePositiveDetermination{
			Note: getNoteForTruePositive(conclusions),
		}
		return e
	}

	if eventType == v2.EventTypeFalsePositiveDetermination {
		e.Data = v2.FalsePositiveDetermination{
			Type: v2.FPTypeVulnerableCodeNotIncludedInPackage,
			Note: getNoteForFalsePositive(conclusions),
		}
		return e
	}

	// This case is unexpected, but it would be worse to assume a TP if not a FP, or
	// vice versa.
	return nil
}

func getNoteForTruePositive(conclusions []triage.Conclusion) string {
	sb := strings.Builder{}
	sb.WriteString("A govulncheck analysis found the following affected symbols in the APK: ")

	var symbolsAtLocationMessage []string
	for _, c := range conclusions {
		if r, ok := c.Reason.(reason); ok {
			symbolsAtLocationMessage = append(
				symbolsAtLocationMessage,
				fmt.Sprintf(
					"%s (at %s)",
					strings.Join(r.affectedSymbols, ", "),
					r.location,
				),
			)
		}
	}

	sb.WriteString(strings.Join(symbolsAtLocationMessage, ", ") + ".")

	return sb.String()
}

func getNoteForFalsePositive(conclusions []triage.Conclusion) string {
	sb := strings.Builder{}
	sb.WriteString("A govulncheck analysis found that none of the known affected symbols were present in the APK, after examining the following paths within the package: ")

	var pathsExamined []string
	for _, c := range conclusions {
		if r, ok := c.Reason.(reason); ok {
			pathsExamined = append(pathsExamined, r.location)
		}
	}

	sb.WriteString(strings.Join(pathsExamined, ", ") + ".")

	return sb.String()
}

const (
	govulncheckDB = "https://vuln.go.dev"
	indexEndpoint = "/index/vulns.json"
)

// runGovulncheck is our entrypoint for running govulncheck on a Go binary (as
// the exe parameter).
func (t *Triager) runGovulncheck(ctx context.Context, p scan.Package) (*vulncheck.Result, error) {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, fmt.Sprintf("runGovulncheck on %s", p.Location))
	defer span.End()

	location := p.Location

	if result, ok := t.govulncheckResultCache[location]; ok {
		return result, nil
	}

	// Find the Go binary in the APK.
	pathInAPK := strings.TrimPrefix(location, "/")
	file, err := t.apkFS.Open(pathInAPK)
	if err != nil {
		return nil, fmt.Errorf("opening file %q: %w", pathInAPK, err)
	}
	ra, ok := file.(io.ReaderAt)
	if !ok {
		return nil, fmt.Errorf("file %q is not a ReaderAt, which is required for govulncheck", location)
	}

	// TODO: implement a smarter client that can cache the DB locally.
	c, err := client.NewClient(govulncheckDB, nil)
	if err != nil {
		return nil, fmt.Errorf("creating DB client: %w", err)
	}

	cfg := &govulncheck.Config{
		ScanLevel: "symbol",
	}
	result, err := vulncheck.Binary(ctx, ra, cfg, c)
	if err != nil {
		return nil, err
	}

	err = file.Close()
	if err != nil {
		return nil, fmt.Errorf("closing file %q: %w", location, err)
	}

	result.Vulns = vulnscan.UniqueVulns(result.Vulns)

	// Save result to make next time fast!
	t.govulncheckResultCache[location] = result

	return result, nil
}

type goVulnDBIndex struct {
	index map[string]goVulnDBIndexEntry
}

type goVulnDBIndexEntry struct {
	ID       string    `json:"id"`
	Modified time.Time `json:"modified"`
	Aliases  []string  `json:"aliases,omitempty"`
}

func (i *goVulnDBIndex) isKnownToGoVulnDB(v scan.Vulnerability) bool {
	_, ok := i.Get(v.ID)
	if ok {
		return true
	}

	for _, alias := range v.Aliases {
		_, ok := i.Get(alias)
		if ok {
			return true
		}
	}

	return false
}

// buildDatastoreForGoVulnDB builds an index of GoVulnDB entries, keyed by
// aliases (like CVE IDs and GHSA IDs).
func (t *Triager) buildDatastoreForGoVulnDB(ctx context.Context) (*goVulnDBIndex, error) {
	if t.datastore != nil {
		// We already have the index, so return it.
		return t.datastore, nil
	}

	t.datastoreGenerationMutex.Lock()
	defer t.datastoreGenerationMutex.Unlock()

	req, err := http.NewRequestWithContext(ctx, "GET", govulncheckDB+indexEndpoint, nil)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var entries []goVulnDBIndexEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}

	index := make(map[string]goVulnDBIndexEntry)
	for _, entry := range entries {
		index[entry.ID] = entry
		for _, alias := range entry.Aliases {
			index[alias] = entry
		}
	}

	return &goVulnDBIndex{index}, nil
}

// Get returns the GoVulnDB index entry for the given ID, or false if it doesn't
// exist.
func (i *goVulnDBIndex) Get(id string) (goVulnDBIndexEntry, bool) {
	entry, ok := i.index[id]
	return entry, ok
}
