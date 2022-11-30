package cli

import (
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "wupdater",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		Short:             "A simple CLI for working with Wolfi GitHub repositories",
	}

	cmd.AddCommand(Update())
	return cmd
}
