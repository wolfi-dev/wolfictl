package advisory

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	v2 "github.com/chainguard-dev/advisory-schema/pkg/advisory/v2"
	"github.com/chainguard-dev/clog"
	"github.com/wolfi-dev/wolfictl/pkg/advisory/secdb"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
)

const apkURL = "{{urlprefix}}/{{reponame}}/{{arch}}/{{pkg.name}}-{{pkg.ver}}.apk"

// BuildSecurityDatabaseOptions contains the options for building a database.
type BuildSecurityDatabaseOptions struct {
	AdvisoryDocIndices []*configs.Index[v2.Document]

	URLPrefix string
	Archs     []string
	Repo      string
}

var (
	ErrNoPackageSecurityData = errors.New("no package security data found")
	ErrorPackageCollision    = errors.New("found multiple advisory documents for the same package")
)

// BuildSecurityDatabase builds an Alpine-style security database from the given options.
func BuildSecurityDatabase(ctx context.Context, opts BuildSecurityDatabaseOptions) ([]byte, error) {
	log := clog.FromContext(ctx)
	var packageEntries []secdb.PackageEntry

	seenPackages := make(map[string]struct{})

	for _, index := range opts.AdvisoryDocIndices {
		var indexPackageEntries []secdb.PackageEntry

		for _, doc := range index.Select().Configurations() {
			if _, exists := seenPackages[doc.Package.Name]; exists {
				// TODO Merge the events between multiple advisories
				log.InfoContextf(ctx, "cannot process additional advisory data for package %q: %v", doc.Package.Name, ErrorPackageCollision)
			}
			seenPackages[doc.Package.Name] = struct{}{}

			if len(doc.Advisories) == 0 {
				continue
			}

			secfixes := make(secdb.Secfixes)

			sort.Slice(doc.Advisories, func(i, j int) bool {
				return doc.Advisories[i].ID < doc.Advisories[j].ID
			})

			for _, advisory := range doc.Advisories {
				if len(advisory.Events) == 0 {
					continue
				}

				sortedEvents := advisory.SortedEvents()
				latest := sortedEvents[len(advisory.Events)-1]

				addVulnToPkgVersion := func(vulnID string) {
					switch latest.Type {
					case v2.EventTypeFixed:
						version := latest.Data.(v2.Fixed).FixedVersion //nolint:errcheck // We're confident in this type assertion
						secfixes[version] = append(secfixes[version], vulnID)
						sort.Strings(secfixes[version])
					case v2.EventTypeFalsePositiveDetermination:
						secfixes[secdb.NAK] = append(secfixes[secdb.NAK], vulnID)
						sort.Strings(secfixes[secdb.NAK])
					}
				}

				// Get vulnerabilities from advisory aliases
				for _, alias := range advisory.Aliases {
					vulnID := alias
					addVulnToPkgVersion(vulnID)
				}
			}

			if len(secfixes) == 0 {
				continue
			}

			pe := secdb.PackageEntry{
				Pkg: secdb.Package{
					Name:     doc.Package.Name,
					Secfixes: secfixes,
				},
			}

			indexPackageEntries = append(indexPackageEntries, pe)
		}

		if len(indexPackageEntries) == 0 {
			// Catch the unexpected case where an advisories directory contains no security data.
			return nil, ErrNoPackageSecurityData
		}

		packageEntries = append(packageEntries, indexPackageEntries...)
	}

	db := secdb.Database{
		APKURL:    apkURL,
		Archs:     opts.Archs,
		Repo:      opts.Repo,
		URLPrefix: opts.URLPrefix,
		Packages:  packageEntries,
	}

	return json.MarshalIndent(db, "", "  ")
}
