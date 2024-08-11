package cli

import (
	"log/slog"
	"os"

	"github.com/chainguard-dev/clog/slag"
	charmlog "github.com/charmbracelet/log"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/version"
)

func New() *cobra.Command {
	var level slag.Level
	cmd := &cobra.Command{
		Use:               "wolfictl",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		Short:             "A CLI helper for developing Wolfi",
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			slog.SetDefault(slog.New(charmlog.NewWithOptions(os.Stderr, charmlog.Options{ReportTimestamp: true, Level: charmlog.Level(level)})))
			return nil
		},
	}
	cmd.PersistentFlags().Var(&level, "log-level", "log level (e.g. debug, info, warn, error)")

	cmd.AddCommand(
		cmdAdvisory(),
		cmdApk(),
		cmdBuild(),
		cmdBump(),
		cmdCheck(),
		cmdGh(),
		cmdImage(),
		cmdLint(),
		cmdRuby(),
		cmdLs(),
		cmdSVG(),
		cmdTest(),
		cmdText(),
		cmdSBOM(),
		cmdScan(),
		cmdVEX(),
		cmdWithdraw(),
		version.Version(),
	)

	return cmd
}
