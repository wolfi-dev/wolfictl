package fetch

import (
	"fmt"
	"strings"

	"chainguard.dev/melange/pkg/config"
)

/*
Validation Rule:
  - Ensures at least one source uses templates for auto-updates
  - Reports hardcoded versions in fetch URLs and git tags when templates are present elsewhere
*/

// Creates a validator with compiled patterns for the package
func newValidator(pkg packageInfo) *validator {
	return &validator{
		pkg:      pkg,
		patterns: buildPackagePatterns(pkg.name, pkg.version),
	}
}

// ValidateFetchTemplating validates that package sources use proper templating to avoid version drift.
func ValidateFetchTemplating(cfg *config.Configuration) error {
	if cfg == nil {
		return nil
	}

	// Skip all validation if auto-updates are disabled or manual-only
	if !cfg.Update.Enabled || cfg.Update.Manual {
		return nil
	}

	sources := extractRawPipelineData(cfg.Root())
	if sources.isEmpty() {
		return nil
	}

	pkg := packageInfo{
		name:    strings.TrimSpace(cfg.Package.Name),
		version: strings.TrimSpace(cfg.Package.Version),
	}

	validator := newValidator(pkg)
	return validator.validateAll(sources)
}

// Runs validation and returns formatted errors
func (v *validator) validateAll(sources sourceData) error {
	var allIssues []string
	allIssues = append(allIssues, v.validateSources(sources)...)

	return v.formatError(allIssues)
}

// Validation: package-level template requirement, individual source hardcoded detection
func (v *validator) validateSources(sources sourceData) []string {
	// Only count version-bearing sources (fetch URLs and git tags, not branches/refs)
	versionBearingSources := len(sources.fetchURLs) + len(sources.gitTags)
	if versionBearingSources == 0 {
		return nil
	}

	foundAnyTemplate := false
	foundVersionAwareTemplate := false
	var untemplatedSources []string
	var hardcodedIssues []string

	// Check fetch URLs for both template presence and hardcoded versions
	for _, uri := range sources.fetchURLs {
		if hasAnyTemplate(uri) {
			foundAnyTemplate = true
		}
		if hasVersionTemplate(uri) {
			foundVersionAwareTemplate = true
		} else {
			untemplatedSources = append(untemplatedSources, fmt.Sprintf("fetch URL: %s", uri))

			// Also check for hardcoded versions in non-templated URLs
			if v.patterns != nil {
				if v.patterns.exactVersionURL.MatchString(uri) {
					hardcodedIssues = append(hardcodedIssues, fmt.Sprintf("fetch URL contains hardcoded package version '%s' for '%s': %s", v.pkg.version, v.pkg.name, uri))
				} else if v.patterns.anyVersionURL.MatchString(uri) {
					hardcodedIssues = append(hardcodedIssues, fmt.Sprintf("fetch URL contains '%s' with hardcoded version (may be out of sync with package.version): %s", v.pkg.name, uri))
				}
			}
		}
	}

	// Check git tags for both template presence and hardcoded versions
	for _, tag := range sources.gitTags {
		if hasAnyTemplate(tag) {
			foundAnyTemplate = true
		}
		if hasVersionTemplate(tag) {
			foundVersionAwareTemplate = true
		} else {
			untemplatedSources = append(untemplatedSources, fmt.Sprintf("git tag: %s", tag))

			// Also check for hardcoded versions in non-templated git tags
			if v.patterns != nil {
				if v.patterns.exactVersionTag.MatchString(tag) {
					hardcodedIssues = append(hardcodedIssues, fmt.Sprintf("git tag contains hardcoded package version: %s", tag))
				} else if v.patterns.packageVersionTag.MatchString(tag) {
					hardcodedIssues = append(hardcodedIssues, fmt.Sprintf("git tag contains '%s' with hardcoded version (may be out of sync with package.version): %s", v.pkg.name, tag))
				}
			}
		}
	}

	// Count templated refs for template requirement validation
	for _, gitData := range sources.gitBranches {
		if gitData.Ref != "" && hasVersionTemplate(gitData.Ref) {
			foundAnyTemplate = true
			foundVersionAwareTemplate = true
		}
	}

	// Apply package-level template requirement
	templateRequirementFails := false
	if versionBearingSources == 1 {
		templateRequirementFails = !foundAnyTemplate
	} else {
		templateRequirementFails = !foundVersionAwareTemplate && !foundAnyTemplate
	}

	var issues []string

	// If package-level template requirement fails, report that
	if templateRequirementFails {
		switch {
		case versionBearingSources == 1 && len(untemplatedSources) > 0:
			cleanSource := strings.Replace(untemplatedSources[0], "fetch URL: ", "(fetch URL) ", 1)
			cleanSource = strings.Replace(cleanSource, "git tag: ", "(git tag) ", 1)
			issues = append(issues, fmt.Sprintf("source lacks templated variables: %s", cleanSource))
		case len(untemplatedSources) > 0:
			issues = append(issues, fmt.Sprintf("no templated variables found in any sources:\n- %s\nAt least one origin should use templates like ${{package.version}} to avoid version drift", strings.Join(untemplatedSources, "\n- ")))
		default:
			issues = append(issues, "no templated variables found in any fetch URLs or git tags; at least one origin should be parameterized (preferably on version) to avoid drift")
		}
	} else if len(hardcodedIssues) > 0 {
		// Package has templates but also has hardcoded versions in some sources
		issues = append(issues, hardcodedIssues...)
	}

	return issues
}

// Formats validation errors consistently
func (v *validator) formatError(allIssues []string) error {
	if len(allIssues) == 0 {
		return nil
	}

	if len(allIssues) == 1 {
		issue := allIssues[0]
		// Don't add template suggestion if the error already contains template guidance or is a template requirement message
		if strings.Contains(issue, "${{package.version}}") || strings.Contains(issue, "source lacks templated variables") || strings.Contains(issue, "no templated variables found") {
			return fmt.Errorf("%s", issue)
		}
		// Add template suggestion for hardcoded version errors
		return fmt.Errorf("%s; check whether this should be derived from ${{package.version}} (or a transform)", issue)
	}

	message := "multiple fetch/git issues found:\n- " + strings.Join(allIssues, "\n- ")
	message += "\nFor version issues: check whether these should be derived from ${{package.version}} (or a transform)"
	return fmt.Errorf("%s", message)
}
