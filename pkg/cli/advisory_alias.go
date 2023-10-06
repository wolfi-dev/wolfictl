package cli

import (
	"github.com/spf13/cobra"
)

func cmdAdvisoryAlias() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "alias",
		Short: "Utilities for viewing and modifying Wolfi advisory aliases",
	}

	cmd.AddCommand(
		cmdAdvisoryAliasDiscover(),
		cmdAdvisoryAliasFind(),
	)

	return cmd
}
