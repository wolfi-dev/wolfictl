package advisory

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"

	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	"gopkg.in/yaml.v3"
)

type ExportOptions struct {
	AdvisoryDocIndices []*configs.Index[v2.Document]
}

// ExportCSV returns a reader of advisory data encoded as CSV.
func ExportCSV(opts ExportOptions) (io.Reader, error) {
	buf := new(bytes.Buffer)
	csvWriter := csv.NewWriter(buf)
	defer csvWriter.Flush()

	// Write the header row
	header := []string{"package", "advisory_id", "event_timestamp", "event_type", "false_positive_type", "note", "fixed_version"}
	err := csvWriter.Write(header)
	if err != nil {
		return nil, err
	}

	for _, index := range opts.AdvisoryDocIndices {
		documents := index.Select().Configurations()

		for _, doc := range documents {
			for _, adv := range doc.Advisories {
				for _, event := range adv.Events {
					var falsePositiveType, note, fixedVersion string

					switch event.Type {
					case v2.EventTypeTruePositiveDetermination:
						note = event.Data.(v2.TruePositiveDetermination).Note

					case v2.EventTypeFalsePositiveDetermination:
						fp, _ := event.Data.(v2.FalsePositiveDetermination) //nolint:errcheck
						falsePositiveType = fp.Type
						note = fp.Note

					case v2.EventTypeFixed:
						fixedVersion = event.Data.(v2.Fixed).FixedVersion

					case v2.EventTypeFixNotPlanned:
						note = event.Data.(v2.FixNotPlanned).Note

					case v2.EventTypeAnalysisNotPlanned:
						note = event.Data.(v2.AnalysisNotPlanned).Note
					}

					row := []string{
						doc.Package.Name,
						adv.ID,
						event.Timestamp.String(),
						event.Type,
						falsePositiveType,
						note,
						fixedVersion,
					}

					if err := csvWriter.Write(row); err != nil {
						return nil, err
					}
				}
			}
		}
	}

	return buf, nil
}

// ExportYAML returns a reader of advisory data encoded as YAML.
func ExportYAML(opts ExportOptions) (io.Reader, error) {
	buf := new(bytes.Buffer)

	for _, index := range opts.AdvisoryDocIndices {
		pkgs := index.Select().Configurations()

		for i, pkg := range pkgs {
			if i != 0 {
				buf.WriteString("---\n")
			}

			d, err := yaml.Marshal(pkg)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal package %q: %v", pkg.Package.Name, err)
			}
			buf.Write(d)
		}
	}

	return buf, nil
}
