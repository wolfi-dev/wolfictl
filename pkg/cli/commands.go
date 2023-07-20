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
		Advisory(),
		Bump(),
		Gh(),
		Apk(),
		Index(),
		GenerateIndex(),
		cmdPod(),
		cmdSVG(),
		cmdText(),
		cmdMake(),
		Check(),
		Lint(),
		Ls(),
		SBOM(),
		Scan(),
		Update(),
		VEX(),
		version.Version(),
	)

	return cmd
}
