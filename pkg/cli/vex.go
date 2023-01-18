package cli

import (
	"fmt"
	"os"

	"chainguard.dev/melange/pkg/build"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/vex"
)

func VEX() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vex",
		Short: "Tools to generate VEX statements for Wolfi packages and images",
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

var vexCfg = vex.Config{
	Distro:     "wolfi",
	DistroRepo: "",
	Author:     "",
	AuthorRole: "",
}

func addPackage(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:           "package [flags] CONFIG [CONFIG]...",
		Example:       "wolfictl vex package --author=joe@doe.com config1.yaml config2.yaml",
		Short:         "Generate a VEX document from package configuration files",
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				cmd.Help() //nolint:errcheck
				return errors.New("too few arguments")
			}

			confs := []*build.Configuration{}
			for _, configPath := range args {
				buildCfg, err := build.ParseConfiguration(configPath)
				if err != nil {
					return err
				}
				confs = append(confs, buildCfg)
			}

			doc, err := vex.FromPackageConfiguration(vexCfg, confs...)
			if err != nil {
				return fmt.Errorf("creating VEX document: %w", err)
			}

			if err := doc.ToJSON(os.Stdout); err != nil {
				return fmt.Errorf("marshaling VEX document: %w", err)
			}

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
create a VEX document containing impact assessments in its advisories and
secfixes.

wolfictl will read the melange config files from an existing wolfi-dev/os clone
or, if not specified, it will clone the repo for you.
`,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				cmd.Help() //nolint:errcheck
				return errors.New("required parameter missing: path to SBOM")
			}

			doc, err := vex.FromSBOM(vexCfg, args[0])
			if err != nil {
				return fmt.Errorf("creating VEX document from SBOM: %w", err)
			}

			if err := doc.ToJSON(os.Stdout); err != nil {
				return fmt.Errorf("marshaling VEX document")
			}

			return nil
		},
	}
	addCommonVexFlags(cmd)
	cmd.Flags().StringVar(&vexCfg.DistroRepo, "repo", "", "path to a local clone of the wolfi-dev/os repo")
	parent.AddCommand(cmd)
}

func addCommonVexFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&vexCfg.Author, "author", "", "author of the VEX document")
	cmd.Flags().StringVar(&vexCfg.AuthorRole, "role", "", "role of the author of the VEX document")
}
