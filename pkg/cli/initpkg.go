package cli

import (
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/initpkg"
)

func InitPkg() *cobra.Command {
	var name, license, version, layout string

	cmd := &cobra.Command{
		Use:  "initpkg",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := initpkg.New(
				initpkg.WithURI(args[0]),
				initpkg.WithName(name),
				initpkg.WithLicense(license),
				initpkg.WithVersion(version),
				initpkg.WithLayout(layout),
			)

			if err != nil {
				return err
			}

			return ctx.Run()
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "name of the package")
	cmd.Flags().StringVar(&license, "license", "", "license of the package")
	cmd.Flags().StringVar(&version, "version", "", "version of the package")
	cmd.Flags().StringVar(&layout, "layout", "", "package source layout to use as a template")

	return cmd
}
