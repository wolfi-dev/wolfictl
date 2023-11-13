package cli

import (
	"github.com/spf13/cobra"
)

func cmdDep() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "dep",
		Aliases:       []string{"dependency"},
		SilenceErrors: true,
		Short:         "Commands for dealing with package dependencies",
	}

	return cmd
}
