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
	anyVersionURL   *regexp.Regexp
	exactVersionTag *regexp.Regexp
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
