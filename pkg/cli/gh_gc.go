package cli

import (
	"github.com/spf13/cobra"
)

func Gc() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "gc",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		Short:             "Garbage collection commands used with GitHub",
	}

	cmd.AddCommand(
		Branch(),
		Issues(),
	)

	return cmd
}
