package cli

import (
	"os"

	"chainguard.dev/melange/pkg/build"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/vex"
)

func VEX() *cobra.Command {
	var author, role string

	cmd := &cobra.Command{
		Use:           "vex",
		Short:         "Generate a VEX document from a package configuration file",
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath := args[0]
			buildCfg, err := build.ParseConfiguration(configPath)
			if err != nil {
				return err
			}

			vexCfg := vex.Config{
				Distro:     "wolfi",
				Author:     author,
				AuthorRole: role,
			}

			doc, err := vex.FromPackageConfiguration(buildCfg, vexCfg)
			if err != nil {
				return err
			}

			err = doc.ToJSON(os.Stdout)
			if err != nil {
				return err
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&author, "author", "", "author of the VEX document")
	cmd.Flags().StringVar(&role, "role", "", "role of the author of the VEX document")

	return cmd
}
