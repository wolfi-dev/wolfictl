package advisory

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/google/osv-scanner/pkg/models"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
)

// OSVOptions contains the options for building an OSV dataset.
type OSVOptions struct {
	// AdvisoryDocIndices is a list of indexes containing Chainguard advisory
	// documents.
	AdvisoryDocIndices []*configs.Index[v2.Document]

	// OutputDirectory is the path to a local directory in which the generated OSV
	// dataset will be written.
	OutputDirectory string

	// Deprecated: Soon we'll always use the "chainguard" ecosystem and not
	// accept any other value.
	Ecosystem string
}

// OSVEcosystem is the name of the OSV ecosystem for Chainguard advisories.
const OSVEcosystem = "Chainguard"

// BuildOSVDataset produces an OSV dataset from Chainguard advisory data, using
// the given set of options.
func BuildOSVDataset(_ context.Context, opts OSVOptions) error {
	osvExport := make(map[string]models.Vulnerability)
	ecosystem := models.Ecosystem(opts.Ecosystem)

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
							Ecosystem: ecosystem,
							Purl:      fmt.Sprintf("pkg:apk/%s/%s", strings.ToLower(string(ecosystem)), doc.Package.Name),
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
							Ecosystem: ecosystem,
							Purl:      fmt.Sprintf("pkg:apk/%s/%s", strings.ToLower(string(ecosystem)), doc.Package.Name),
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
						// check if there is a CGA duplicate across different packages
						for i := range entry.Affected {
							if !strings.EqualFold(doc.Package.Name, entry.Affected[i].Package.Name) {
								log.Fatalf("maybe a CGA id conflict for %s: %s against %s ", adv.ID, doc.Package.Name, entry.Affected[i].Package.Name)
							}
						}

						entry.Affected = append(entry.Affected, tempAffected)
						if updatedTime.After(entry.Modified) {
							entry.Modified = updatedTime
						}
						osvExport[adv.ID] = entry
					} else {
						// new entry
						aliases := []string{adv.ID}
						aliases = append(aliases, adv.Aliases...)
						temp := models.Vulnerability{
							ID:       adv.ID,
							Aliases:  aliases,
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

	all := []models.Vulnerability{}
	for _, k := range keys {
		// for the all.json we just need the id and modified date
		temp := models.Vulnerability{
			ID:       osvExport[k].ID,
			Modified: osvExport[k].Modified,
		}
		all = append(all, temp)

		e, err := osvExport[k].MarshalJSON()
		if err != nil {
			log.Fatal(err)
		}

		// TODO(luhring): This should probably be moved to a test. But it's also failing
		//  for a separate reason, which is that we're using the "wolfi" ecosystem, which
		//  isn't valid according to the OSV schema. We'll have to submit the
		//  "chainguard" ecosystem upstream.
		//
		// err = schema.Validate(result) if err != nil {
		// 	log.Fatalf("failed to validate OSV JSON Schema for %s: %v", k, err)
		// }

		filepath := path.Join(opts.OutputDirectory, fmt.Sprintf("%s.json", k))
		err = os.WriteFile(filepath, e, 0o644)
		if err != nil {
			log.Fatal(err)
		}
	}

	allData, err := json.Marshal(all)
	if err != nil {
		log.Fatal(err)
	}

	filepath := path.Join(opts.OutputDirectory, "all.json")
	err = os.WriteFile(filepath, allData, 0o644)
	if err != nil {
		log.Fatal(err)
	}

	return nil
}
