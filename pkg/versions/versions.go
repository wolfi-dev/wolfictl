package versions

import (
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
	// we need to override the default comparison as some releases indicate build data in the release version
	if equal(u[i].Segments(), u[j].Segments()) {
		if u[j].Metadata() != "" {
			if u[j].Metadata() > u[i].Metadata() {
				return true
			}
		}
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

// ByLatestStrings is like ByLatest but lets the user pass in strings instead of Version objects.
type ByLatestStrings []string

func (by ByLatestStrings) Len() int {
	return len(by)
}

func (by ByLatestStrings) Less(i, j int) bool {
	vi, err := NewVersion(by[i])
	if err != nil {
		return false
	}
	vj, err := NewVersion(by[j])
	if err != nil {
		return false
	}
	if equal(vi.Segments(), vj.Segments()) {
		if vj.Metadata() != "" {
			if vj.Metadata() > vi.Metadata() {
				return false
			}
		}
	}
	return vi.GreaterThan(vj)
}

func (by ByLatestStrings) Swap(i, j int) {
	by[i], by[j] = by[j], by[i]
}
