package advisory

import (
	"encoding/json"
	"errors"
	"sort"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/samber/lo"
	"github.com/wolfi-dev/wolfictl/pkg/advisory/secdb"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v1 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v1"
)

const apkURL = "{{urlprefix}}/{{reponame}}/{{arch}}/{{pkg.name}}-{{pkg.ver}}.apk"

// BuildDatabaseOptions contains the options for building a database.
type BuildDatabaseOptions struct {
	AdvisoryCfgIndices []*configs.Index[v1.Document]

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
				entries := cfg.Advisories[vuln]

				if len(entries) == 0 {
					continue
				}

				latest := Latest(entries)
				switch latest.Status {
				case vex.StatusFixed:
					version := latest.FixedVersion
					secfixes[version] = append(secfixes[version], vuln)
				case vex.StatusNotAffected:
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
