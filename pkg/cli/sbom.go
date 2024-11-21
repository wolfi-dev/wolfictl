package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	sbomSyft "github.com/anchore/syft/syft/sbom"
	"github.com/chainguard-dev/clog"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/cli/styles"
	"github.com/wolfi-dev/wolfictl/pkg/sbom"
	"golang.org/x/exp/slices"
)

const (
	sbomFormatOutline  = "outline"
	sbomFormatSyftJSON = "syft-json"
)

func cmdSBOM() *cobra.Command {
	p := &sbomParams{}
	cmd := &cobra.Command{
		Use:           "sbom <path/to/package.apk>",
		Short:         "Generate a software bill of materials (SBOM) for an APK file",
		Hidden:        true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := clog.NewLogger(newLogger(p.verbosity))
			ctx := clog.WithLogger(cmd.Context(), logger)

			if !slices.Contains([]string{sbomFormatOutline, sbomFormatSyftJSON}, p.outputFormat) {
				return fmt.Errorf("invalid output format %q, must be one of [%s]", p.outputFormat, strings.Join([]string{sbomFormatOutline, sbomFormatSyftJSON}, ", "))
			}

			// TODO: Bring input retrieval options in line with `wolfictl scan`.

			apkFilePath := args[0]
			apkFile, err := os.Open(apkFilePath)
			if err != nil {
				return fmt.Errorf("failed to open apk file: %w", err)
			}

			if p.outputFormat == outputFormatOutline {
				fmt.Printf("🔎 Scanning %q\n", apkFilePath)
			}

			var s *sbomSyft.SBOM
			if p.disableSBOMCache {
				s, err = sbom.Generate(ctx, apkFilePath, apkFile, p.distro)
			} else {
				s, err = sbom.CachedGenerate(ctx, apkFilePath, apkFile, p.distro)
			}
			if err != nil {
				return fmt.Errorf("failed to generate SBOM: %w", err)
			}

			switch p.outputFormat {
			case sbomFormatOutline:
				tree := newPackageTree(s.Artifacts.Packages.Sorted())
				fmt.Println(tree.render())

			case sbomFormatSyftJSON:
				jsonReader, err := sbom.ToSyftJSON(s)
				if err != nil {
					return fmt.Errorf("failed to encode SBOM: %w", err)
				}

				_, err = io.Copy(os.Stdout, jsonReader)
				if err != nil {
					return fmt.Errorf("failed to write SBOM: %w", err)
				}
			}

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type sbomParams struct {
	outputFormat     string
	distro           string
	disableSBOMCache bool
	verbosity        int
}

func (p *sbomParams) addFlagsTo(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&p.outputFormat, "output", "o", sbomFormatOutline, "output format (outline, syft-json)")
	cmd.Flags().StringVar(&p.distro, "distro", "wolfi", "distro to report in SBOM")
	cmd.Flags().BoolVarP(&p.disableSBOMCache, "disable-sbom-cache", "D", false, "don't use the SBOM cache")
	addVerboseFlag(&p.verbosity, cmd)
}

type packageTree struct {
	packagesByLocation map[string][]pkg.Package
}

func newPackageTree(packages []pkg.Package) *packageTree {
	packagesByLocation := map[string][]pkg.Package{}
	for i := range packages {
		p := packages[i]
		locs := lo.Map(p.Locations.ToSlice(), func(l file.Location, _ int) string {
			return "/" + l.RealPath
		})

		location := strings.Join(locs, ", ")
		packagesByLocation[location] = append(packagesByLocation[location], p)
	}
	return &packageTree{
		packagesByLocation: packagesByLocation,
	}
}

func (t *packageTree) render() string {
	locations := lo.Keys(t.packagesByLocation)
	sort.Strings(locations)

	var lines []string
	for i, location := range locations {
		var treeStem, verticalLine string
		if i == len(locations)-1 {
			treeStem = "└── "
			verticalLine = " "
		} else {
			treeStem = "├── "
			verticalLine = "│"
		}

		line := treeStem + fmt.Sprintf("📄 %s", location)
		lines = append(lines, line)

		packages := t.packagesByLocation[location]

		sort.SliceStable(packages, func(i, j int) bool {
			return packages[i].Name < packages[j].Name
		})

		for i := range packages {
			p := packages[i]
			line := fmt.Sprintf(
				"%s       📦 %s %s %s",
				verticalLine,
				p.Name,
				p.Version,
				styles.Faint().Render("("+string(p.Type)+")"),
			)
			lines = append(lines, line)
		}

		lines = append(lines, verticalLine)
	}

	return strings.Join(lines, "\n")
}
