package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/vuln/pkg/client"
	"golang.org/x/vuln/pkg/govulncheck"
	vulnscan "golang.org/x/vuln/pkg/scan"
	"golang.org/x/vuln/pkg/vulncheck"
)

const (
	govulncheckDB = "https://vuln.go.dev"
	indexEndpoint = "/index/vulns.json"
)

// runGovulncheck is our entrypoint for running govulncheck on a Go binary (as
// the exe parameter).
func runGovulncheck(ctx context.Context, exe io.ReaderAt) (*vulncheck.Result, error) {
	// TODO: implement a smarter client that can cache the DB locally.
	c, err := client.NewClient(govulncheckDB, nil)
	if err != nil {
		return nil, fmt.Errorf("creating DB client: %w", err)
	}

	cfg := &govulncheck.Config{
		ScanLevel: "symbol",
	}
	result, err := vulncheck.Binary(ctx, exe, cfg, c)
	if err != nil {
		return nil, err
	}

	result.Vulns = vulnscan.UniqueVulns(result.Vulns)

	return result, nil
}

type GoVulnDBIndex struct {
	index map[string]GoVulnDBIndexEntry
}

type GoVulnDBIndexEntry struct {
	ID       string    `json:"id"`
	Modified time.Time `json:"modified"`
	Aliases  []string  `json:"aliases,omitempty"`
}

// BuildIndexForGoVulnDB builds an index of GoVulnDB entries, keyed by aliases
// (like CVE IDs and GHSA IDs).
func BuildIndexForGoVulnDB(ctx context.Context) (*GoVulnDBIndex, error) {
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

	var entries []GoVulnDBIndexEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}

	index := make(map[string]GoVulnDBIndexEntry)
	for _, entry := range entries {
		index[entry.ID] = entry
		for _, alias := range entry.Aliases {
			index[alias] = entry
		}
	}

	return &GoVulnDBIndex{index}, nil
}

// Get returns the GoVulnDB index entry for the given ID, or false if it doesn't
// exist.
func (i *GoVulnDBIndex) Get(id string) (GoVulnDBIndexEntry, bool) {
	entry, ok := i.index[id]
	return entry, ok
}
