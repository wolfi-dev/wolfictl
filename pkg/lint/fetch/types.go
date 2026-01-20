package fetch

import (
	"regexp"
)

// Holds git checkout reference information for templating validation
type gitRefInfo struct {
	Ref string
}

// Holds compiled regex patterns for a specific package
type packagePatterns struct {
	exactVersionURL   *regexp.Regexp
	anyVersionURL     *regexp.Regexp
	exactVersionTag   *regexp.Regexp
	packageVersionTag *regexp.Regexp
}

// Holds extracted pipeline data
type sourceData struct {
	fetchURLs   []string
	gitTags     []string
	gitBranches []gitRefInfo
}

// Holds package metadata
type packageInfo struct {
	name    string
	version string
}

// Handles validation logic with pre-compiled patterns
type validator struct {
	pkg      packageInfo
	patterns *packagePatterns
}

// Checks if sourceData contains any data
func (s sourceData) isEmpty() bool {
	return len(s.fetchURLs) == 0 && len(s.gitTags) == 0 && len(s.gitBranches) == 0
}
