package advisory

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
	_ "github.com/santhosh-tekuri/jsonschema/v5/httploader" // to be able to download the schema from the URL

	"github.com/google/osv-scanner/pkg/models"
	"github.com/samber/lo"
	"gopkg.in/yaml.v3"

	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
)

const OSVSchema = "https://raw.githubusercontent.com/ossf/osv-schema/main/validation/schema.json"

type ExportOptions struct {
	AdvisoryDocIndices []*configs.Index[v2.Document]
	Ecosystem          models.Ecosystem
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

func ExportOSV(opts ExportOptions, output string) error {
	osvExport := make(map[string]models.Vulnerability)

	for _, index := range opts.AdvisoryDocIndices {
		documents := index.Select().Configurations()

		for _, doc := range documents {
			for _, adv := range doc.Advisories {
				sortedEvents := adv.SortedEvents()

				var updatedTime time.Time
				tempAffected := models.Affected{}

				for _, event := range sortedEvents {
					switch event.Type {
					case v2.EventTypeFixed:
						tempAffected.Package = models.Package{
							Name:      doc.Package.Name,
							Ecosystem: opts.Ecosystem,
							Purl:      fmt.Sprintf("pkg:apk/%s/%s", opts.Ecosystem, doc.Package.Name),
						}
						tempAffected.Ranges = []models.Range{
							{
								Type: models.RangeEcosystem,
								Events: []models.Event{
									{
										Introduced: "0",
									},
									{
										Fixed: event.Data.(v2.Fixed).FixedVersion,
									},
								},
							},
						}
						updatedTime = time.Time(event.Timestamp)
					case v2.EventTypeFalsePositiveDetermination:
						tempAffected.Package = models.Package{
							Name:      doc.Package.Name,
							Ecosystem: opts.Ecosystem,
							Purl:      fmt.Sprintf("pkg:apk/%s/%s", opts.Ecosystem, doc.Package.Name),
						}
						tempAffected.Ranges = []models.Range{
							{
								Type: models.RangeEcosystem,
								Events: []models.Event{
									{
										Introduced: "0",
									},
									{
										Fixed: "0",
									},
								},
								DatabaseSpecific: map[string]interface{}{
									"false_positive": true,
								},
							},
						}
						updatedTime = time.Time(event.Timestamp)
					default:
						continue
					}

					if len(tempAffected.Ranges) == 0 {
						continue
					}

					entry, ok := osvExport[adv.ID]
					if ok {
						entry.Affected = append(entry.Affected, tempAffected)

						if updatedTime.After(entry.Modified) {
							entry.Modified = updatedTime
						}

						osvExport[adv.ID] = entry
					} else {
						temp := models.Vulnerability{
							ID:       fmt.Sprintf("%s-%s", strings.ToUpper(string(opts.Ecosystem)), adv.ID),
							Aliases:  adv.Aliases,
							Affected: []models.Affected{tempAffected},
						}
						if updatedTime.After(entry.Modified) {
							temp.Modified = updatedTime
						}

						osvExport[adv.ID] = temp
					}
				}
			}
		}
	}

	keys := make([]string, 0, len(osvExport))
	for k := range osvExport {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// get the OSV schema to validate
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	schema, err := compiler.Compile(OSVSchema)
	if err != nil {
		log.Fatal(err)
	}

	all := []models.Vulnerability{}
	for _, k := range keys {
		all = append(all, osvExport[k])

		e, err := osvExport[k].MarshalJSON()
		if err != nil {
			log.Fatal(err)
		}

		// to run the validate schema
		var result any
		err = json.Unmarshal(e, &result)
		if err != nil {
			log.Fatalf("failed to unmarshall:%v", err)
		}
		err = schema.Validate(result)
		if err != nil {
			log.Fatalf("failed to validate OSV JSON Schema for %s: %v", k, err)
		}

		filepath := path.Join(output, fmt.Sprintf("%s-%s.json", strings.ToUpper(string(opts.Ecosystem)), k))
		err = os.WriteFile(filepath, e, 0o644) //nolint: gosec
		if err != nil {
			log.Fatal(err)
		}
	}

	allData, err := json.Marshal(all)
	if err != nil {
		log.Fatal(err)
	}

	filepath := path.Join(output, "all.json")
	err = os.WriteFile(filepath, allData, 0o644) //nolint: gosec
	if err != nil {
		log.Fatal(err)
	}

	return nil
}
