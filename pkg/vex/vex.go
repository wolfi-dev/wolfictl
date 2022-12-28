package vex

import (
	"time"

	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/vex/pkg/vex"
)

type Config struct {
	DocumentID, Distro, Author, AuthorRole string
	DocumentTimestamp                      time.Time
}

// FromPackageConfiguration generates a new VEX document for the Wolfi package described by the build.Configuration.
func FromPackageConfiguration(buildCfg build.Configuration, vexCfg Config) (vex.VEX, error) {
	doc := vex.New()

	doc.ID = vexCfg.DocumentID
	doc.Timestamp = &vexCfg.DocumentTimestamp
	doc.Author = vexCfg.Author
	doc.AuthorRole = vexCfg.AuthorRole

	purls := buildCfg.PackageURLs(vexCfg.Distro)

	doc.Statements = statementsFromConfiguration(buildCfg, *doc.Timestamp, purls)

	return doc, nil
}

func statementsFromConfiguration(cfg build.Configuration, documentTimestamp time.Time, purls []string) []vex.Statement {
	// We should also add a lint rule for when advisories obviate particular secfixes items.
	secfixesStatements := statementsFromSecfixes(cfg.Secfixes, purls)
	advisoriesStatements := statementsFromAdvisories(cfg.Advisories, purls)

	// don't include "not_affected" statements from secfixes that are obviated by statements from advisories
	notAffectedVulns := make(map[string]struct{})
	for _, stmt := range advisoriesStatements {
		if stmt.Status == vex.StatusNotAffected {
			notAffectedVulns[stmt.Vulnerability] = struct{}{}
		}
	}
	var statements []vex.Statement
	for _, sfStmt := range secfixesStatements {
		if _, seen := notAffectedVulns[sfStmt.Vulnerability]; !seen {
			statements = append(statements, sfStmt)
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
		for _, entry := range entries {
			stmts = append(stmts, statementFromAdvisoryContent(entry, v, purls))
		}
	}

	return stmts
}

func statementFromAdvisoryContent(content build.AdvisoryContent, vulnerability string, purls []string) vex.Statement {
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
