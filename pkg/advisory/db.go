package advisory

import (
	"encoding/json"
	"errors"
	"sort"

	"github.com/samber/lo"
	"github.com/wolfi-dev/wolfictl/pkg/advisory/secdb"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	"github.com/wolfi-dev/wolfictl/pkg/configs/advisory"
)

const apkURL = "{{urlprefix}}/{{reponame}}/{{arch}}/{{pkg.name}}-{{pkg.ver}}.apk"

// BuildDatabaseOptions contains the options for building a database.
type BuildDatabaseOptions struct {
	AdvisoryCfgIndices []*configs.Index[advisory.Document]

	URLPrefix string
	Archs     []string
	Repo      string
}

var ErrNoPackageSecurityData = errors.New("no package security data found")

// BuildDatabase builds a security database from the given options.
func BuildDatabase(opts BuildDatabaseOptions) ([]byte, error) {
	var packageEntries []secdb.PackageEntry

	for _, index := range opts.AdvisoryCfgIndices {
		var cfgPackageEntries []secdb.PackageEntry

		for _, cfg := range index.Select().Configurations() {
			if len(cfg.Advisories) == 0 {
				continue
			}

			advisoryVulns := lo.Keys(cfg.Advisories)
			sort.Strings(advisoryVulns)

			secfixes := make(secdb.Secfixes)

			for _, vuln := range advisoryVulns {
				events := cfg.Advisories[vuln].Events

				if len(events) == 0 {
					continue
				}

				latest := Latest(events)
				switch d := latest.Data.(type) {
				case advisory.FixedEvent:
					version := d.FixedPackageVersion
					secfixes[version] = append(secfixes[version], vuln)
				case advisory.FalsePositiveDeterminationEvent:
					secfixes[secdb.NAK] = append(secfixes[secdb.NAK], vuln)
				}
			}

			if len(secfixes) == 0 {
				continue
			}

			pe := secdb.PackageEntry{
				Pkg: secdb.Package{
					Name:     cfg.Package.Name,
					Secfixes: secfixes,
				},
			}

			cfgPackageEntries = append(cfgPackageEntries, pe)
		}

		if len(cfgPackageEntries) == 0 {
			// Catch the unexpected case where an advisories directory contains no security data.
			return nil, ErrNoPackageSecurityData
		}

		packageEntries = append(packageEntries, cfgPackageEntries...)
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
