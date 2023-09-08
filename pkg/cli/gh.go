package cli

import "github.com/spf13/cobra"

func cmdGh() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "gh",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		Short:             "Commands used to interact with GitHub",
	}

	cmd.AddCommand(
		Release(),
		Gc(),
	)

	return cmd
}
