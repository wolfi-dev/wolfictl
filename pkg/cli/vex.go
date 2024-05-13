package cli

import (
	"log"

	"github.com/spf13/cobra"
)

func cmdVEX() *cobra.Command {
	cmd := &cobra.Command{
		Deprecated: "This command does nothing, and will be removed in a future version.",
		Use:        "vex",
		Short:      "Tools to generate VEX statements for Wolfi packages and images",
		Long: `wolfictl vex: Tools to generate VEX statements for Wolfi packages and images

The vex family of subcommands interacts with Wolfi data and configuration
files to generate Vulnerability Exploitability eXchange (VEX) documents to
inform downstream consumer how vulnerabilities impact Wolfi packages and images
that use them.

wolfictl can generate VEX data by reading the melange configuration files
of each package and additional information coming from external documents.
There are currently two VEX subcommands:

 wolfictl vex package: Generates VEX documents from a list of melange configs

 wolfictl vex sbom: Generates a VEX document by reading an image SBOM

For more information please see the help sections if these subcommands. To know
more about the VEX tooling powering wolfictl see: https://openvex.dev/


`,
		SilenceErrors: true,
	}

	addPackage(cmd)
	addSBOM(cmd)
	return cmd
}

func addPackage(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:           "package CONFIG [CONFIG]...",
		Example:       "wolfictl vex package --author=joe@doe.com config1.yaml config2.yaml",
		Short:         "Generate a VEX document from package configuration files",
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			log.Print("Did nothing!")
			return nil
		},
	}
	addCommonVexFlags(cmd)
	parent.AddCommand(cmd)
}

func addSBOM(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:     "sbom [flags] sbom.spdx.json",
		Example: "wolfictl vex sbom --author=joe@doe.com sbom.spdx.json",
		Short:   "Generate a VEX document from wolfi packages listed in an SBOM",
		Long: `wolfictl vex sbom: Generate a VEX document from wolfi packages listed in an SBOM

The vex sbom subcommand generates VEX documents describing how vulnerabilities
impact Wolfi packages listed in an SBOM. This subcommand reads SPDX SBOMs and
will recognize and capture all packages identified as Wolfi OS components
by its purl. For example, if an SBOM contains a package with the following
purl:

	pkg:apk/wolfi/curl@7.87.0-r0

wolfictl will read the melange configuration file that created the package and
create a VEX document containing impact assessments in its advisories.

wolfictl will read the melange config files from an existing wolfi-dev/os clone
or, if not specified, it will clone the repo for you.
`,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			log.Print("Did nothing!")
			return nil
		},
	}
	addCommonVexFlags(cmd)
	var s string
	cmd.Flags().StringVar(&s, "repo", "", "path to a local clone of the wolfi-dev/os repo")
	parent.AddCommand(cmd)
}

func addCommonVexFlags(cmd *cobra.Command) {
	var s string
	cmd.Flags().StringVar(&s, "author", "", "author of the VEX document")
	cmd.Flags().StringVar(&s, "role", "", "role of the author of the VEX document")
}
