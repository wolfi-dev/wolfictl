package secdb

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

const NAK = "0"
