package advisory

import (
	"encoding/json"

	"github.com/wolfi-dev/wolfictl/pkg/configs"
	"github.com/wolfi-dev/wolfictl/pkg/configs/advisory"
)

const apkURL = "{{urlprefix}}/{{reponame}}/{{arch}}/{{pkg.name}}-{{pkg.ver}}.apk"

// BuildDatabaseOptions contains the options for building a database.
type BuildDatabaseOptions struct {
	AdvisoryCfgs *configs.Index[advisory.Document]

	URLPrefix string
	Archs     []string
	Repo      string
}

// BuildDatabase builds a security database from the given options.
func BuildDatabase(opts BuildDatabaseOptions) ([]byte, error) {
	cfgs := opts.AdvisoryCfgs.Select().Configurations()

	var packageEntries []PackageEntry

	for _, cfg := range cfgs {
		if len(cfg.Secfixes) == 0 {
			continue
		}

		pe := PackageEntry{
			Pkg: Package{
				Name:     cfg.Package.Name,
				Secfixes: Secfixes(cfg.Secfixes),
			},
		}

		packageEntries = append(packageEntries, pe)
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
