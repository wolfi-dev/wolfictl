package advisory

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/osv-scanner/pkg/models"
	"github.com/samber/lo"
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
	advisoryIDsToModels := make(map[string]models.Vulnerability)
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

					entry, ok := advisoryIDsToModels[adv.ID]
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
						advisoryIDsToModels[adv.ID] = entry
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

						advisoryIDsToModels[adv.ID] = temp
					}
				}
			}
		}
	}

	ids := lo.Keys(advisoryIDsToModels)
	sort.Strings(ids)

	// write the all.json ("the index") and individual advisory files

	var indexEntries []models.Vulnerability

	for _, id := range ids {
		advisoryModel := advisoryIDsToModels[id]

		// for the all.json, we just need the id and modified date
		indexEntry := models.Vulnerability{
			ID:       advisoryModel.ID,
			Modified: advisoryModel.Modified,
		}
		indexEntries = append(indexEntries, indexEntry)

		// TODO(luhring): This should probably be moved to a test. But it's also failing
		//  for a separate reason, which is that we're using the "wolfi" ecosystem, which
		//  isn't valid according to the OSV schema. We'll have to submit the
		//  "chainguard" ecosystem upstream.
		//
		// err = schema.Validate(result) if err != nil {
		// 	log.Fatalf("failed to validate OSV JSON Schema for %s: %v", id, err)
		// }

		advisoryFilepath := filepath.Join(opts.OutputDirectory, fmt.Sprintf("%s.json", id))
		advisoryFile, err := os.Create(advisoryFilepath)
		if err != nil {
			return fmt.Errorf("creating file for OSV advisory %q: %w", id, err)
		}

		enc := json.NewEncoder(advisoryFile)
		enc.SetIndent("", "  ")
		err = enc.Encode(advisoryModel)
		if err != nil {
			return fmt.Errorf("encoding OSV advisory %q to JSON: %w", id, err)
		}
	}

	const indexFileName = "all.json"
	indexFilepath := filepath.Join(opts.OutputDirectory, indexFileName)
	indexFile, err := os.Create(indexFilepath)
	if err != nil {
		return fmt.Errorf("creating file for OSV index: %w", err)
	}

	enc := json.NewEncoder(indexFile)
	enc.SetIndent("", "  ")
	err = enc.Encode(indexEntries)
	if err != nil {
		return fmt.Errorf("encoding OSV index to JSON: %w", err)
	}

	return nil
}
