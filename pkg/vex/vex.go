package vex

import (
	"fmt"
	"time"

	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/vex/pkg/vex"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type Config struct {
	Distro, Author, AuthorRole string
}

// FromPackageConfiguration generates a new VEX document for the Wolfi package described by the build.Configuration.
func FromPackageConfiguration(buildCfg *build.Configuration, vexCfg Config) (vex.VEX, error) {
	doc := vex.New()

	doc.ID = generateDocumentID(buildCfg.Package.Name)
	doc.Author = vexCfg.Author
	doc.AuthorRole = vexCfg.AuthorRole

	purls := buildCfg.PackageURLs(vexCfg.Distro)

	if doc.Timestamp == nil {
		// We don't expect this case, since `vex.New()` sets a document timestamp.
		return vex.VEX{}, errors.New("document timestamp must be set")
	}

	doc.Statements = statementsFromConfiguration(buildCfg, *doc.Timestamp, purls)

	return doc, nil
}

func statementsFromConfiguration(cfg *build.Configuration, documentTimestamp time.Time, purls []string) []vex.Statement {
	// We should also add a lint rule for when advisories obviate particular secfixes items.
	secfixesStatements := statementsFromSecfixes(cfg.Secfixes, purls)
	advisoriesStatements := statementsFromAdvisories(cfg.Advisories, purls)

	// don't include "not_affected" statements from secfixes that are obviated by statements from advisories
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

func generateDocumentID(packageName string) string {
	return fmt.Sprintf("vex-%s-%s", packageName, uuid.New())
}
