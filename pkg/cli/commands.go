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
	var level = slag.Level(slog.LevelWarn)

	cmd := &cobra.Command{
		Use:               "wolfictl",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		Short:             "A CLI helper for developing Wolfi",
		PersistentPreRun: func(*cobra.Command, []string) {
			slog.SetDefault(slog.New(charmlog.NewWithOptions(os.Stderr, charmlog.Options{ReportTimestamp: true, Level: charmlog.Level(level)})))
		},
	}
	cmd.PersistentFlags().Var(&level, "log-level", "log level (e.g. debug, info, warn, error)")

	cmd.AddCommand(
		cmdAdvisory(),
		cmdApk(),
		cmdBump(),
		cmdCheck(),
		cmdGh(),
		cmdImage(),
		cmdLint(),
		cmdRuby(),
		cmdLs(),
		cmdRestore(),
		cmdSVG(),
		cmdText(),
		cmdSBOM(),
		cmdScan(),
		cmdVEX(),
		cmdWithdraw(),
		version.Version(),
	)

	return cmd
}
