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
		cmdPod(),
		cmdSVG(),
		cmdText(),
		cmdCheck(),
		cmdLint(),
		cmdLs(),
		cmdSBOM(),
		cmdScan(),
		cmdUpdate(),
		cmdVEX(),
		version.Version(),
	)

	return cmd
}
