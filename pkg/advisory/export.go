package advisory

import (
	"bytes"
	"encoding/csv"
	"io"
	"sort"

	"github.com/samber/lo"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	"github.com/wolfi-dev/wolfictl/pkg/configs/advisory"
)

type ExportOptions struct {
	AdvisoryCfgIndices []*configs.Index[advisory.Document]
}

// Export returns a reader of advisory data encoded as CSV.
func Export(opts ExportOptions) (io.Reader, error) {
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
