package advisory

import (
	"bytes"
	"encoding/csv"
	"io"
	"log"
	"sort"

	"github.com/samber/lo"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	"github.com/wolfi-dev/wolfictl/pkg/configs/advisory"
	"gopkg.in/yaml.v3"
)

type ExportOptions struct {
	AdvisoryCfgIndices []*configs.Index[advisory.Document]
}

// ExportCSV returns a reader of advisory data encoded as CSV.
func ExportCSV(opts ExportOptions) (io.Reader, error) {
	buf := new(bytes.Buffer)
	csvWriter := csv.NewWriter(buf)
	defer csvWriter.Flush()

	// Write the header row
	header := []string{"package", "advisory", "status", "fixed_version", "justification", "impact", "action"}
	err := csvWriter.Write(header)
	if err != nil {
		return nil, err
	}

	for _, index := range opts.AdvisoryCfgIndices {
		pkgs := index.Select().Configurations()

		for _, pkg := range pkgs {
			ids := lo.Keys(pkg.Advisories)
			sort.Strings(ids)

			for _, advisoryID := range ids {
				entries := pkg.Advisories[advisoryID]
				latest := Latest(entries)

				if latest == nil {
					continue
				}

				row := []string{
					pkg.Package.Name,
					advisoryID,
					string(latest.Status),
					latest.FixedVersion,
					string(latest.Justification),
					latest.ImpactStatement,
					latest.ActionStatement,
				}

				if err := csvWriter.Write(row); err != nil {
					return nil, err
				}
			}
		}
	}

	return buf, nil
}

// Export returns a reader of advisory data encoded as CSV.
func ExportYAML(opts ExportOptions) (io.Reader, error) {
	buf := new(bytes.Buffer)

	for _, index := range opts.AdvisoryCfgIndices {
		pkgs := index.Select().Configurations()

		for i, pkg := range pkgs {
			if i != 0 {
				buf.WriteString("---\n")
			}

			d, err := yaml.Marshal(pkg)
			if err != nil {
				log.Fatalf("error: %v", err)
			}
			buf.Write(d)
		}
	}

	return buf, nil
}
