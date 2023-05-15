package advisory

import (
	"encoding/json"
	"errors"

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
	var packageEntries []PackageEntry

	for _, index := range opts.AdvisoryCfgIndices {
		var cfgPackageEntries []PackageEntry

		for _, cfg := range index.Select().Configurations() {
			if len(cfg.Secfixes) == 0 {
				continue
			}

			pe := PackageEntry{
				Pkg: Package{
					Name:     cfg.Package.Name,
					Secfixes: Secfixes(cfg.Secfixes),
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

	db := Database{
		APKURL:    apkURL,
		Archs:     opts.Archs,
		Repo:      opts.Repo,
		URLPrefix: opts.URLPrefix,
		Packages:  packageEntries,
	}

	return json.MarshalIndent(db, "", "  ")
}

type Database struct {
	APKURL    string         `json:"apkurl"`
	Archs     []string       `json:"archs"`
	Repo      string         `json:"reponame"`
	URLPrefix string         `json:"urlprefix"`
	Packages  []PackageEntry `json:"packages"`
}

type PackageEntry struct {
	Pkg Package `json:"pkg"`
}

type Package struct {
	Name     string   `json:"name"`
	Secfixes Secfixes `json:"secfixes"`
}

type Secfixes map[string][]string
