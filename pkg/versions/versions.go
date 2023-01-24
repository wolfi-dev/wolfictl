package versions

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/go-version"
)

type Interface interface {
	// Len is the number of elements in the collection.
	Len() int

	// Less reports whether the element with index i must sort before the element with index j.
	// If both Less(i, j) and Less(j, i) are false, then the elements at index i and j are considered equal.
	Less(i, j int) bool

	// Swap swaps the elements with indexes i and j.
	Swap(i, j int)
}

func (u ByLatest) Len() int {
	return len(u)
}

func (u ByLatest) Swap(i, j int) {
	u[i], u[j] = u[j], u[i]
}

func (u ByLatest) Less(i, j int) bool {
	// we need to override the default prerelease version comparison as we use 1.2.3ab1 rather than 1.2.3-ab1
	// we use this version format so we can use the same version in melange configs and have apk resolve correct versions
	if equal(u[i].Segments(), u[j].Segments()) {
		//nolint:gosimple // incorrect behaviour if using ``
		re := regexp.MustCompile("\\d+|\\D+")
		iparts := re.FindAllString(u[i].Prerelease(), -1)
		if len(iparts) != 2 {
			return false
		}
		jparts := re.FindAllString(u[j].Prerelease(), -1)
		if len(jparts) != 2 {
			return false
		}
		// compare the string prefixes
		if strings.Compare(iparts[0], jparts[0]) == -1 {
			return true
		}

		// compare the integer suffixes
		isuffix, err := strconv.Atoi(iparts[1])
		if err != nil {
			return false
		}
		jsuffix, err := strconv.Atoi(jparts[1])
		if err != nil {
			return false
		}

		return isuffix < jsuffix
	}
	return u[i].LessThan(u[j])
}

type ByLatest []*version.Version

func equal(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// NewVersion some older versions in wolfi contain an underscore to separate pre-release
func NewVersion(v string) (*version.Version, error) {
	v = strings.ReplaceAll(v, "_", "")
	return version.NewVersion(v)
}
