package advisory

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/samber/lo"
	"gopkg.in/yaml.v3"

	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
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

// ImporAdvisoriesYAML import and yaml Advisories data and present as a config index struct
func ImporAdvisoriesYAML(inputData string) (tempDir string, documents *configs.Index[v2.Document], err error) {
	inputAdv, err := os.ReadFile(inputData)
	if err != nil {
		return "", nil, fmt.Errorf("unable to create output file: %v", err)
	}

	yamlDocs := bytes.Split(inputAdv, []byte("\n---\n"))
	// Unmarshal YAML documents
	var docs []v2.Document
	for _, doc := range yamlDocs {
		var pkg v2.Document
		err = yaml.Unmarshal(doc, &pkg)
		if err != nil {
			return "", nil, fmt.Errorf("unable to unmarshall input file: %v", err)
		}

		docs = append(docs, pkg)
	}

	tempDir = os.TempDir()
	for _, doc := range docs {
		f, err := os.Create(filepath.Join(tempDir, fmt.Sprintf("%s.advisories.yaml", doc.Name())))
		if err != nil {
			return "", nil, fmt.Errorf("failed to create adv file: %v", err)
		}

		d, err := yaml.Marshal(doc)
		if err != nil {
			return "", nil, fmt.Errorf("failed to marshal package %q: %v", doc.Package.Name, err)
		}
		_, err = f.Write(d)
		if err != nil {
			return "", nil, fmt.Errorf("failed save data to file: %v", err)
		}

		f.Close()
	}

	advisoryFsys := rwos.DirFS(tempDir)
	advisoryDocIndices, err := v2.NewIndex(context.Background(), advisoryFsys)
	if err != nil {
		return "", nil, fmt.Errorf("unable to index advisory configs for directory %q: %v", tempDir, err)
	}

	return tempDir, advisoryDocIndices, nil
}
