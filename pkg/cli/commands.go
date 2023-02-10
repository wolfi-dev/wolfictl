package cli

import (
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "wolfictl",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		Short:             "A simple CLI for working with Wolfi GitHub repositories",
	}

	cmd.AddCommand(
		Update(),
		Lint(),
		VEX(),
		Advisory(),
		Bump(),
		Gh(),
		Apk(),
		Index(),
		GenerateIndex(),
	)

	return cmd
}
