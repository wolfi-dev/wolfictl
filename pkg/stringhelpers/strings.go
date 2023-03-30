package stringhelpers

import (
	"net/url"
	"path/filepath"
	"regexp"
)

// RegexpSplit splits a string into an array using the regexSep as a separator
func RegexpSplit(text, regexSeperator string) []string {
	reg := regexp.MustCompile(regexSeperator)
	indexes := reg.FindAllStringIndex(text, -1)
	lastIdx := 0
	result := make([]string, len(indexes)+1)
	for i, element := range indexes {
		result[i] = text[lastIdx:element[0]]
		lastIdx = element[1]
	}
	result[len(indexes)] = text[lastIdx:]
	return result
}

func IsURI(s string) bool {
	_, err := url.Parse(s)
	return err == nil
}

func IsFilePath(s string) bool {
	return filepath.IsAbs(s)
}
