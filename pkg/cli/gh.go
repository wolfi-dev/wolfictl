package cli

import "github.com/spf13/cobra"

func Gh() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "gh",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		Short:             "Commands used to interact with GitHub",
	}

	cmd.AddCommand(
		Release(),
	)

	return cmd
}
