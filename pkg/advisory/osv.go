package advisory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"chainguard.dev/melange/pkg/config"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/samber/lo"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
)

// OSVOptions contains the options for building an OSV dataset.
type OSVOptions struct {
	// AdvisoryDocIndices is a list of indexes containing Chainguard advisory
	// documents.
	//
	// TODO(luhring): We should move toward unifying all advisory repositories into
	//  a single collection of all advisory documents. At that point, we won't need
	//  to use multiple advisory indices here.
	AdvisoryDocIndices []*configs.Index[v2.Document]

	// PackageConfigIndices is a list of indexes containing Chainguard package build
	// configurations. The address of each slice item is expected to correspond to
	// the address of the corresponding item in AdvisoryDocIndices.
	PackageConfigIndices []*configs.Index[config.Configuration]

	// AddedEcosystems is a list of ecosystems to be added to the OSV dataset. The
	// address of each slice item is expected to correspond to the address of the
	// corresponding item in AdvisoryDocIndices. The length of this slice is
	// expected to be the same as the length of AdvisoryDocIndices.
	//
	// Use an empty string at slice locations where no additional ecosystems are
	// needed.
	//
	// For example, to add the "wolfi" ecosystem to the advisories in the first
	// index, and no additional ecosystems to the advisories in the second index:
	//
	//   AddedEcosystems: []string{"wolfi", ""}
	//
	// TODO(luhring): We should move toward unifying the Chainguard and Wolfi
	//  ecosystems, so that we don't need to add the "wolfi" ecosystem here, and
	//  we'll just use "Chainguard" always. At that point, we can remove this
	//  option entirely.
	AddedEcosystems []string

	// OutputDirectory is the path to a local directory in which the generated OSV
	// dataset will be written.
	OutputDirectory string
}

// OSVEcosystem is the name of the OSV ecosystem for Chainguard advisories.
const OSVEcosystem models.Ecosystem = "Chainguard"

// BuildOSVDataset produces an OSV dataset from Chainguard advisory data, using
// the given set of options.
func BuildOSVDataset(_ context.Context, opts OSVOptions) error {
	if len(opts.AdvisoryDocIndices) != len(opts.AddedEcosystems) {
		return fmt.Errorf("length of AdvisoryDocIndices and AddedEcosystems must be equal: use an empty string to signal no added ecosystem")
	}

	if len(opts.PackageConfigIndices) == 0 {
		return fmt.Errorf("at least one package config index must be provided")
	}

	// Do one time upfront, instead of per advisory document: Find out the
	// subpackages for all defined packages in the packages repos.
	pkgNameToSubpackages := make(map[string][]string)
	for _, packageConfigIndex := range opts.PackageConfigIndices {
		// We assume that each package name is unique across all package repos.

		cfgs := packageConfigIndex.Select().Configurations()
		for i := range cfgs {
			cfg := cfgs[i]

			var subpackages []string
			for i := range cfg.Subpackages {
				sp := cfg.Subpackages[i]
				subpackages = append(subpackages, sp.Name)
			}
			sort.Strings(subpackages)
			pkgNameToSubpackages[cfg.Package.Name] = subpackages
		}
	}

	advisoryIDsToModels := make(map[string]models.Vulnerability)

	for i, index := range opts.AdvisoryDocIndices {
		// See if we need to add additional ecosystems for this particular advisories
		// index.
		addedEcosystem := opts.AddedEcosystems[i]
		ecosystems := []models.Ecosystem{OSVEcosystem}
		if addedEcosystem != "" {
			ecosystems = append(ecosystems, models.Ecosystem(addedEcosystem))
		}

		documents := index.Select().Configurations()
		for _, doc := range documents {
			// We'll have one or more affected packages listed for each advisory. We'll
			// always include the origin package in the Chainguard ecosystem as an 'affected
			// package'. If there are subpackages, we'll add an 'affected package' for each
			// of those. Finally, we'll add any specified additional ecosystems (e.g.
			// "wolfi") to produce additional 'affected packages' for each of the
			// origin+subpackages.
			//
			// The final count of 'affected packages' for each advisory should be:
			//
			//   (1 + number of subpackages) * (1 + number of additional ecosystems)

			pkgName := doc.Package.Name
			pkgs := append([]string{pkgName}, pkgNameToSubpackages[pkgName]...)

			var affectedPackages []models.Package
			for _, pkg := range pkgs {
				for _, ecosystem := range ecosystems {
					affectedPackages = append(affectedPackages, models.Package{
						Name:      pkg,
						Ecosystem: ecosystem,
						Purl:      createPurl(pkg, ecosystem),
					})
				}
			}

			for _, adv := range doc.Advisories {
				latestEvent := adv.Latest()
				advisoryLastUpdated := time.Time(latestEvent.Timestamp)

				var affectedRange models.Range

				switch latestEvent.Type {
				case v2.EventTypeFixed:
					if d, ok := latestEvent.Data.(v2.Fixed); ok {
						affectedRange = rangeForFixed(d.FixedVersion)
					} else {
						return fmt.Errorf("unexpected data type for fixed event: %T (advisory index %d, package %q, advisory ID %q)", latestEvent.Data, i, pkgName, adv.ID)
					}
				case v2.EventTypeFalsePositiveDetermination:
					affectedRange = rangeForFalsePositive()
				default:
					// We don't yet produce OSV data for other event types.
					continue
				}

				// Note: The OSV data should include our advisory ID itself among the listed aliases.
				aliases := append([]string{adv.ID}, adv.Aliases...)

				affecteds := make([]models.Affected, 0, len(affectedPackages))
				for _, pkg := range affectedPackages {
					affecteds = append(affecteds, models.Affected{
						Package: pkg,
						Ranges:  []models.Range{affectedRange},
					})
				}

				entry := models.Vulnerability{
					ID:       adv.ID,
					Aliases:  aliases,
					Affected: affecteds,
					Modified: advisoryLastUpdated,
				}

				advisoryIDsToModels[adv.ID] = entry
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

func createPurl(pkgName string, ecosystem models.Ecosystem) string {
	return fmt.Sprintf("pkg:apk/%s/%s", strings.ToLower(string(ecosystem)), pkgName)
}

func rangeForFixed(fixedVersion string) models.Range {
	return models.Range{
		Type: models.RangeEcosystem,
		Events: []models.Event{
			{
				Introduced: "0",
			},
			{
				Fixed: fixedVersion,
			},
		},
	}
}

func rangeForFalsePositive() models.Range {
	return models.Range{
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
	}
}
