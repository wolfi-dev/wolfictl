package cli

import "github.com/spf13/cobra"

func cmdImage() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "image",
		Short: "(Experimental) Commands for working with container images that use Wolfi",
	}

	cmd.AddCommand(
		cmdImageAPK(),
	)

	return cmd
}
