package dag

// Package represents an individual package.
type Package interface {
	Name() string
	Version() string
	String() string // String shows the combination name and version
	Source() string // Source shows the source repository of the package
	Resolved() bool // if this is resolved or just an interim
}
