package fetch

import (
	"fmt"
	"regexp"
)

// Common regex patterns used throughout the validation
var (
	anyTemplateRegex     = regexp.MustCompile(`\$\{\{[^}]+\}\}`)
	versionTemplateRegex = regexp.MustCompile(`\$\{\{\s*(package\.(version|full-version)|vars\..*version.*)[^}]*\}\}`)
)

// Regex pattern templates for building package-specific patterns
const (
	exactVersionURLPattern = `(?:^|/)%s(?:[-_]v?%s(?:\.tar\.(?:gz|bz2|xz)|\.zip|\.tgz|\.tbz2|\.txz)|/v?%s/)`
	anyVersionURLPattern   = `(?:^|/)%s(?:[-_]v?\d+\.\d+(?:\.\d+)?(?:[-+][\w\d.]+)?|/v?\d+\.\d+(?:\.\d+)?(?:[-+][\w\d.]+)?/)`
	exactVersionTagPattern = `^v?%s$`
	anyVersionTagPattern   = `^%s[-_]v?\d+\.\d+(?:\.\d+)?(?:[-+][\w\d.]+)?$`
)

// Creates compiled regex patterns for package-specific validation
func buildPackagePatterns(packageName, packageVersion string) *packagePatterns {
	if packageName == "" || packageVersion == "" {
		return nil
	}

	escName := regexp.QuoteMeta(packageName)
	escVer := regexp.QuoteMeta(packageVersion)

	return &packagePatterns{
		exactVersionURL:   regexp.MustCompile(fmt.Sprintf(exactVersionURLPattern, escName, escVer, escVer)),
		anyVersionURL:     regexp.MustCompile(fmt.Sprintf(anyVersionURLPattern, escName)),
		exactVersionTag:   regexp.MustCompile(fmt.Sprintf(exactVersionTagPattern, escVer)),
		packageVersionTag: regexp.MustCompile(fmt.Sprintf(anyVersionTagPattern, escName)),
	}
}

// If a string contains any template variable
func hasAnyTemplate(s string) bool {
	return anyTemplateRegex.MatchString(s)
}

// If a string contains version-related template variables
func hasVersionTemplate(s string) bool {
	return versionTemplateRegex.MatchString(s)
}
