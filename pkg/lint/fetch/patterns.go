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
	anyVersionURLPattern   = `(?:^|/)%s(?:[-_]v?\d+\.\d+(?:\.\d+)?(?:[-+][\w\d.]+)?|/v?\d+\.\d+(?:\.\d+)?(?:[-+][\w\d.]+)?/)`
	exactVersionTagPattern = `^v?%s$`
)

// Creates compiled regex patterns for package-specific validation
func buildPackagePatterns(packageName, packageVersion string) (*packagePatterns, error) {
	if packageName == "" || packageVersion == "" {
		return nil, fmt.Errorf("package name and version must be non-empty, got name='%s' version='%s'", packageName, packageVersion)
	}

	escName := regexp.QuoteMeta(packageName)
	escVer := regexp.QuoteMeta(packageVersion)

	return &packagePatterns{
		anyVersionURL:   regexp.MustCompile(fmt.Sprintf(anyVersionURLPattern, escName)),
		exactVersionTag: regexp.MustCompile(fmt.Sprintf(exactVersionTagPattern, escVer)),
	}, nil
}

// If a string contains any template variable
func hasAnyTemplate(s string) bool {
	return anyTemplateRegex.MatchString(s)
}

// If a string contains version-related template variables
func hasVersionTemplate(s string) bool {
	return versionTemplateRegex.MatchString(s)
}
