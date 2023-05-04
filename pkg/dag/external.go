package dag

import "fmt"

// danglingPackage a holding point for a package that was not resolved anywhere.
// Only used if WithAllowUnresolved is set.
type danglingPackage struct {
	name string
}

func (d danglingPackage) Name() string {
	return d.name
}
func (d danglingPackage) Version() string {
	return ""
}
func (d danglingPackage) String() string {
	return fmt.Sprintf("%s:", d.name)
}
func (d danglingPackage) Source() string {
	return "unknown"
}
func (d danglingPackage) Resolved() bool {
	return false
}

// externalPackage a holding point for a package that was resolved outside, i.e. not locall.
type externalPackage struct {
	name    string
	version string
	source  string
}

func (e externalPackage) Name() string {
	return e.name
}
func (e externalPackage) Version() string {
	return e.version
}
func (e externalPackage) String() string {
	return fmt.Sprintf("%s:%s", e.name, e.version)
}
func (e externalPackage) Source() string {
	return e.source
}
func (e externalPackage) Resolved() bool {
	return true
}
