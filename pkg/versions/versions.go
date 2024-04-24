package versions

import (
	"strconv"
	"strings"

	"github.com/hashicorp/go-version"
)

const apkEpochPrefix = "r"

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
		if u[j].Prerelease() != "" {
			if u[i].Prerelease() != "" && string(u[j].Prerelease()[0]) == apkEpochPrefix && string(u[i].Prerelease()[0]) == apkEpochPrefix {
				ujInt, err := strconv.ParseInt(u[j].Prerelease()[1:], 10, 64)
				isNumeric := true
				if err != nil {
					isNumeric = false
				}

				uiInt, err := strconv.ParseInt(u[i].Prerelease()[1:], 10, 64)
				if err != nil {
					isNumeric = false
				}

				if !isNumeric {
					if u[j].Prerelease()[1:] > u[i].Prerelease()[1:] {
						return false
					}
				}
				return uiInt > ujInt
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
		// Prerelease information is anything that comes after the "-" in the
		// version.
		// If Prerelease information begins with a "r" anything that comes after "r" is treated as a numeric for comparison.
		// This handles comparisons were `0.0.0-r9` is lower than `0.0.0-r10`.
		if vj.Prerelease() != "" {
			if vi.Prerelease() != "" && string(vj.Prerelease()[0]) == apkEpochPrefix && string(vi.Prerelease()[0]) == apkEpochPrefix {
				vjInt, err := strconv.ParseInt(vj.Prerelease()[1:], 10, 64)
				isNumeric := true
				if err != nil {
					isNumeric = false
				}

				viInt, err := strconv.ParseInt(vi.Prerelease()[1:], 10, 64)
				if err != nil {
					isNumeric = false
				}

				if !isNumeric {
					if vj.Prerelease()[1:] > vi.Prerelease()[1:] {
						return false
					}
				}
				return viInt > vjInt
			}
		}
	}
	return vi.GreaterThan(vj)
}

func (by ByLatestStrings) Swap(i, j int) {
	by[i], by[j] = by[j], by[i]
}
