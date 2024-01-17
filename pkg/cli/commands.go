package cli

import (
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/version"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "wolfictl",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		Short:             "A CLI helper for developing Wolfi",
	}

	cmd.AddCommand(
		cmdAdvisory(),
		cmdBuild(),
		cmdBump(),
		cmdGh(),
		cmdApk(),
		cmdIndex(),
		cmdSVG(),
		cmdText(),
		cmdCheck(),
		cmdLint(),
		cmdRuby(),
		cmdLs(),
		cmdSBOM(),
		cmdScan(),
		cmdUpdate(),
		cmdVEX(),
		cmdWithdraw(),
		version.Version(),
	)

	return cmd
}
