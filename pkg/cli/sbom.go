package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	sbomSyft "github.com/anchore/syft/syft/sbom"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/sbompackages"
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
			ctx := cmd.Context()

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
				tree, err := sbompackages.Render(s.Artifacts.Packages.Sorted())
				if err != nil {
					return fmt.Errorf("rendering package tree: %w", err)
				}
				fmt.Println(tree)

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
}

func (p *sbomParams) addFlagsTo(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&p.outputFormat, "output", "o", sbomFormatOutline, "output format (outline, syft-json)")
	cmd.Flags().StringVar(&p.distro, "distro", "wolfi", "distro to report in SBOM")
	cmd.Flags().BoolVarP(&p.disableSBOMCache, "disable-sbom-cache", "D", false, "don't use the SBOM cache")
}
