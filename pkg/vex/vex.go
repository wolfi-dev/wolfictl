package vex

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	purl "github.com/package-url/packageurl-go"
	"gopkg.in/yaml.v3"
	"sigs.k8s.io/release-sdk/git"

	"chainguard.dev/apko/pkg/sbom/generator/spdx"
	"chainguard.dev/melange/pkg/build"

	"chainguard.dev/vex/pkg/ctl"
	"chainguard.dev/vex/pkg/vex"
)

type Config struct {
	Distro, Author, AuthorRole, DistroRepo string
}

// FromSBOM parses an SPDX SBOM and returns a VEX document describing
// vulnerability impact to any wolfi packages lsited in it.
func FromSBOM(vexCfg Config, sbomPath string) (*vex.VEX, error) {
	// Parse the SBOM file
	sbom, err := parseSBOM(sbomPath)
	if err != nil {
		return nil, fmt.Errorf("parsing SBOM: %w", err)
	}

	// Search for all packages in the SBOM describing the distro
	// apks we care about
	purls := extractSBOMPurls(vexCfg, sbom)

	// get the melange package configurations for all listed APKs
	configs, err := getPackageConfigurations(vexCfg, purls)
	if err != nil {
		return nil, fmt.Errorf("reading package configurations: %w", err)
	}

	// This slice will contain one vex for each product in the SBOM
	// that contains wolfi packages
	allVexDocs := []*vex.VEX{}

	// Lets create documents for each product
	for product, prodPurls := range purls {
		// Build the config list for this product
		confs := []*build.Configuration{}
		for _, p := range prodPurls {
			for loopPurl, conf := range configs {
				if loopPurl == p.ToString() {
					confs = append(confs, conf)
				}
			}
		}

		doc, err := FromPackageConfiguration(vexCfg, confs...)
		if err != nil {
			return nil, fmt.Errorf("generating VEX document from package configurations: %w", err)
		}

		// Doc generated. But now, we need to change the statements so that
		// they talk about the product in the SBOM, not the Wolfi apk
		for i := range doc.Statements {
			doc.Statements[i].Subcomponents = doc.Statements[i].Products
			doc.Statements[i].Products = []string{product}
		}
		allVexDocs = append(allVexDocs, doc)
	}
	mergeOpts := ctl.MergeOptions{
		Author:     vexCfg.Author,
		AuthorRole: vexCfg.Author,
	}
	doc, err := ctl.New().Merge(context.Background(), &mergeOpts, allVexDocs)
	if err != nil {
		return nil, fmt.Errorf("merging product VEXes: %w", err)
	}

	return doc, nil
}

// getPackageConfigurations gets a list of purls and returns the melange build
// configuration used to build them
func getPackageConfigurations(vexCfg Config, purls map[string][]purl.PackageURL) (map[string]*build.Configuration, error) {
	if len(purls) == 0 {
		return map[string]*build.Configuration{}, nil
	}

	repoURL := ""
	// In case we expand this to read configs from elsewhere
	if vexCfg.Distro == "wolfi" {
		repoURL = "https://github.com/wolfi-dev/os.git"
	}

	// Clone the wolfi distro
	repo, err := git.CloneOrOpenRepo("", repoURL, !strings.HasPrefix(repoURL, "https://"))
	if err != nil {
		return nil, fmt.Errorf("cloning %s distro: %w", vexCfg.Distro, err)
	}

	// If we're cloning to a temp dir, remove it after use
	if vexCfg.DistroRepo == "" {
		defer os.RemoveAll(repo.Dir())
	}

	// Flatten the purl list
	flatPurls := map[string]purl.PackageURL{}
	for _, prodPurls := range purls {
		for _, p := range prodPurls {
			flatPurls[p.ToString()] = p
		}
	}

	// Index the configuration files
	configIndex, err := indexMelangeConfigsDir(repo.Dir())
	if err != nil {
		return nil, fmt.Errorf("indexing configuration directory: %w", err)
	}

	// Parse all package configurations
	configs := map[string]*build.Configuration{}
	for _, p := range flatPurls {
		if _, ok := configIndex[p.Name]; !ok {
			// Probably should warn here about missing config
			continue
		}
		buildCfg, err := build.ParseConfiguration(configIndex[p.Name])
		if err != nil {
			return nil, fmt.Errorf("parsing %s melange config: %w", p.Name, err)
		}
		configs[p.ToString()] = buildCfg
	}

	return configs, nil
}

// FromPackageConfiguration generates a new VEX document for the Wolfi package described by the build.Configuration.
func FromPackageConfiguration(vexCfg Config, buildCfg ...*build.Configuration) (*vex.VEX, error) {
	id, err := generateDocumentID(buildCfg)
	if err != nil {
		return nil, fmt.Errorf("generating doc ID: %w", err)
	}

	docs := []*vex.VEX{}
	for _, conf := range buildCfg {
		subdoc := vex.New()
		purls := conf.PackageURLs(vexCfg.Distro)
		subdoc.Statements = statementsFromConfiguration(conf, *subdoc.Timestamp, purls)
		docs = append(docs, &subdoc)
	}

	mergeOpts := &ctl.MergeOptions{
		DocumentID: id,
		Author:     vexCfg.Author,
		AuthorRole: vexCfg.AuthorRole,
	}

	vexctl := ctl.New()
	doc, err := vexctl.Merge(context.Background(), mergeOpts, docs)
	if err != nil {
		return nil, fmt.Errorf("merging vex documents: %w", err)
	}
	return doc, nil
}

// indexMelangeConfigsDir reads the distro config directory and
// returns an indexed map where keys are packages and values are
// its connfiguration file.
func indexMelangeConfigsDir(dirPath string) (map[string]string, error) {
	finfo, err := os.Stat(dirPath)
	if err != nil {
		return nil, fmt.Errorf("checking the config directory")
	}
	if !finfo.IsDir() {
		return nil, errors.New("distro config path is not a directory")
	}

	files, err := filepath.Glob(fmt.Sprintf("%s/*.yaml", dirPath))
	if err != nil {
		return nil, fmt.Errorf("listing configuration files")
	}

	confMap := map[string]string{}
	for _, f := range files {
		buildCfg, err := build.ParseConfiguration(f)
		if err != nil {
			return nil, fmt.Errorf("parsing %s config: %w", f, err)
		}
		confMap[buildCfg.Package.Name] = f

		for i := range buildCfg.Subpackages {
			confMap[buildCfg.Subpackages[i].Name] = f
		}
	}
	return confMap, nil
}

// extractPackagePurls returns all purls describing distro apks found
// in elements related to a SPDX package
//
//nolint:gocritic
func extractPackagePurls(vexCfg Config, sbom *spdx.Document, spdxID string, seen *map[string]struct{}) []purl.PackageURL {
	purls := []purl.PackageURL{}
	for _, r := range sbom.Relationships {
		if r.Element != spdxID {
			continue
		}
		if _, ok := (*seen)[r.Related]; ok {
			continue
		}
		(*seen)[r.Related] = struct{}{}
		subpurls := extractPackagePurls(vexCfg, sbom, r.Related, seen)
		purls = append(purls, subpurls...)
		for _, subpackage := range sbom.Packages {
			if subpackage.ID != r.Related {
				continue
			}
			for _, ref := range subpackage.ExternalRefs {
				if ref.Type != "purl" {
					continue
				}
				// If malformed, just skip it
				p, err := purl.FromString(ref.Locator)
				if err != nil {
					continue
				}

				if p.Namespace == vexCfg.Distro {
					purls = append(purls, p)
				}
			}
		}
	}
	return purls
}

// extractSBOMPurls reads an SBOM and returns the purls identifying
// packages from the distribution.
func extractSBOMPurls(vexCfg Config, sbom *spdx.Document) map[string][]purl.PackageURL {
	purls := map[string][]purl.PackageURL{}
	for _, elementID := range sbom.DocumentDescribes {
		packagePurls := extractPackagePurls(vexCfg, sbom, elementID, &map[string]struct{}{})
		if len(packagePurls) == 0 {
			continue
		}

		descPurl := ""
		for i := range sbom.Packages {
			if sbom.Packages[i].ID != elementID {
				continue
			}
			for _, ref := range sbom.Packages[i].ExternalRefs {
				if ref.Type == "purl" {
					descPurl = ref.Locator
				}
			}
		}

		if descPurl != "" {
			purls[descPurl] = packagePurls
		}
	}
	return purls
}

// parseSBOM gets an SPDX-json file and returns a parsed SBOM
func parseSBOM(sbomPath string) (*spdx.Document, error) {
	sbom := &spdx.Document{}
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		return nil, fmt.Errorf("opening SBOM file: %w", err)
	}

	if err := json.Unmarshal(data, sbom); err != nil {
		return nil, fmt.Errorf("unmarshaling SBOM data: %w", err)
	}

	return sbom, nil
}

func statementsFromConfiguration(cfg *build.Configuration, documentTimestamp time.Time, purls []string) []vex.Statement {
	// We should also add a lint rule for when advisories obviate particular secfixes items.
	secfixesStatements := statementsFromSecfixes(cfg.Secfixes, purls)
	advisoriesStatements := statementsFromAdvisories(cfg.Advisories, purls)

	// don't include "not_affected" statements from secfixes that are obviated
	// by statements from advisories
	notAffectedVulns := make(map[string]struct{})
	for i := range advisoriesStatements {
		if advisoriesStatements[i].Status == vex.StatusNotAffected {
			notAffectedVulns[advisoriesStatements[i].Vulnerability] = struct{}{}
		}
	}
	var statements []vex.Statement
	for i := range secfixesStatements {
		if _, seen := notAffectedVulns[secfixesStatements[i].Vulnerability]; !seen {
			statements = append(statements, secfixesStatements[i])
		}
	}

	statements = append(statements, advisoriesStatements...)

	// TODO: also find and weed out duplicate "fixed" statements
	vex.SortStatements(statements, documentTimestamp)
	return statements
}

func statementsFromAdvisories(advisories build.Advisories, purls []string) []vex.Statement {
	var stmts []vex.Statement

	for v, entries := range advisories {
		for i := range entries {
			stmts = append(stmts, statementFromAdvisoryContent(&entries[i], v, purls))
		}
	}

	return stmts
}

func statementFromAdvisoryContent(
	content *build.AdvisoryContent, vulnerability string, purls []string,
) vex.Statement {
	return vex.Statement{
		Vulnerability:   vulnerability,
		Status:          content.Status,
		Justification:   content.Justification,
		ActionStatement: content.ActionStatement,
		ImpactStatement: content.ImpactStatement,
		Products:        purls,
		Timestamp:       &content.Timestamp,
	}
}

func statementsFromSecfixes(secfixes build.Secfixes, purls []string) []vex.Statement {
	var stmts []vex.Statement

	for packageVersion, vulnerabilities := range secfixes {
		for _, v := range vulnerabilities {
			stmts = append(stmts, statementFromSecfixesItem(packageVersion, v, purls))
		}
	}

	return stmts
}

func statementFromSecfixesItem(pkgVersion, vulnerability string, purls []string) vex.Statement {
	status := determineStatus(pkgVersion)

	return vex.Statement{
		Vulnerability: vulnerability,
		Status:        status,
		Products:      purls,
	}
}

func determineStatus(packageVersion string) vex.Status {
	if packageVersion == "0" {
		return vex.StatusNotAffected
	}

	return vex.StatusFixed
}

// generateDocumentID generate a deterministic document ID based
// on the configuration data contents
func generateDocumentID(configs []*build.Configuration) (string, error) {
	hashes := []string{}
	for _, c := range configs {
		data, err := yaml.Marshal(c)
		if err != nil {
			return "", fmt.Errorf("marshaling melange configuration: %w", err)
		}
		h := sha256.New()
		if _, err := h.Write(data); err != nil {
			return "", fmt.Errorf("hashing melange configuration: %w", err)
		}
		hashes = append(hashes, fmt.Sprintf("%x", h.Sum(nil)))
	}

	sort.Strings(hashes)
	h := sha256.New()
	if _, err := h.Write([]byte(strings.Join(hashes, ":"))); err != nil {
		return "", fmt.Errorf("hashing config files: %w", err)
	}

	// One hash to rule them all
	return fmt.Sprintf("vex-%s", fmt.Sprintf("%x", h.Sum(nil))), nil
}
