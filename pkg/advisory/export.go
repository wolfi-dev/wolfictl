package advisory

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"

	_ "github.com/santhosh-tekuri/jsonschema/v5/httploader" // to be able to download the schema from the URL

	"github.com/samber/lo"
	"gopkg.in/yaml.v3"

	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
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
				sortedEvents := adv.SortedEvents()

				for _, event := range sortedEvents {
					var falsePositiveType, note, fixedVersion string

					switch event.Type {
					case v2.EventTypeTruePositiveDetermination:
						if event.Data != nil {
							note = event.Data.(v2.TruePositiveDetermination).Note
						}

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

					case v2.EventTypePendingUpstreamFix:
						note = event.Data.(v2.PendingUpstreamFix).Note
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
		docs := index.Select().Configurations()

		for i, doc := range docs {
			// Sort events for each advisory
			doc.Advisories = lo.Map(doc.Advisories, func(adv v2.Advisory, _ int) v2.Advisory {
				adv.Events = adv.SortedEvents()
				return adv
			})

			if i != 0 {
				buf.WriteString("---\n")
			}

			d, err := yaml.Marshal(doc)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal package %q: %v", doc.Package.Name, err)
			}
			buf.Write(d)
		}
	}

	return buf, nil
}
