package sbompackages

import (
	"fmt"
	"sort"
	"strings"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/samber/lo"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/tree"
	"github.com/wolfi-dev/wolfictl/pkg/cli/styles"
)

func Render(packages []pkg.Package) (string, error) {
	if len(packages) == 0 {
		return "", nil
	}

	sort.SliceStable(packages, func(i, j int) bool {
		iLoc := renderLocation(packages[i])
		jLoc := renderLocation(packages[j])
		if iLoc != jLoc {
			return iLoc < jLoc
		}

		return packages[i].Name < packages[j].Name
	})

	t, err := tree.New(packages, func(p pkg.Package) []string {
		pathParts := []string{
			"",
			fmt.Sprintf("📄 %s", renderLocation(p)),
			fmt.Sprintf(
				"📦 %s %s %s",
				p.Name,
				p.Version,
				styles.Faint().Render("("+string(p.Type)+")"),
			),
		}

		return pathParts
	})
	if err != nil {
		return "", err
	}

	return t.Render(), nil
}

func renderLocation(p pkg.Package) string {
	locs := lo.Map(p.Locations.ToSlice(), func(l file.Location, _ int) string {
		return "/" + l.RealPath
	})

	return strings.Join(locs, ", ")
}
