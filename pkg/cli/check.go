package cli

import (
	"github.com/spf13/cobra"
)

func cmdCheck() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "check",
		Aliases:       []string{"checks"},
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Subcommands used for CI checks in Wolfi",
	}
	cmd.AddCommand(
		Diff(),
		SoName(),
	)
	return cmd
}
