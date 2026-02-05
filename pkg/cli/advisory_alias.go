package cli

import (
	"github.com/spf13/cobra"
)

func cmdAdvisoryAlias() *cobra.Command {
	cmd := &cobra.Command{
		Use:        "alias",
		Short:      "Commands for discovering vulnerability aliases",
		Deprecated: advisoryDeprecationMessage,
	}

	cmd.AddCommand(
		cmdAdvisoryAliasDiscover(),
		cmdAdvisoryAliasFind(),
	)

	return cmd
}
