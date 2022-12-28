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

 wolfictl vex packages: Generates VEX documents from a list of melange configs

 wolfictl vex sbom: Generates a VEX document by reading an image SBOM

For more information please see the help sections if these subcommands. To know
more about the VEX tooling powering wolfictk see: https://github.com/chainguard-dev/vex


`,
		SilenceErrors: true,
	}

	addPackages(cmd)

	return cmd
}

func addPackages(parent *cobra.Command) {
	var author, role string
	cmd := &cobra.Command{
		Use:           "packages [flags] CONFIG [CONFIG]...",
		Example:       "wolfictl vex packages --author=joe@doe.com config1.yaml config2.yaml",
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

			vexCfg := vex.Config{
				Distro:     "wolfi",
				Author:     author,
				AuthorRole: role,
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
	cmd.Flags().StringVar(&author, "author", "", "author of the VEX document")
	cmd.Flags().StringVar(&role, "role", "", "role of the author of the VEX document")
	parent.AddCommand(cmd)
}

func addSBOM(parent *cobra.Command) {
	var author, role string
	cmd := &cobra.Command{
		Use:           "sbom [flags] sbom.spdx.json",
		Example:       "wolfictl vex sbom --author=joe@doe.com sbom.spdx.json",
		Short:         "Generate a VEX document from wolfi packages listed in an SBOM",
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				cmd.Help() //nolint:errcheck
				return errors.New("required paramter missing: path to SBOM")
			}

			vexCfg := vex.Config{
				Distro:     "wolfi",
				Author:     author,
				AuthorRole: role,
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
	cmd.Flags().StringVar(&author, "author", "", "author of the VEX document")
	cmd.Flags().StringVar(&role, "role", "", "role of the author of the VEX document")
	parent.AddCommand(cmd)
}
