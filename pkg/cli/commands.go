package cli

import (
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "update",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		Short:             "Attempts to converts files into melange configuration files",
	}

	cmd.AddCommand(Update())
	return cmd
}
