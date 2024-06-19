package cli

import (
	"log/slog"
	"os"

	"chainguard.dev/apko/pkg/log"
	charmlog "github.com/charmbracelet/log"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/version"
)

func New() *cobra.Command {
	var logPolicy []string
	var level log.CharmLogLevel
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
	cmd.PersistentFlags().StringSliceVar(&logPolicy, "log-policy", []string{"builtin:stderr"}, "log policy (e.g. builtin:stderr, /tmp/log/foo)")
	cmd.PersistentFlags().Var(&level, "log-level", "log level (e.g. debug, info, warn, error)")

	cmd.AddCommand(
		cmdAdvisory(),
		cmdApk(),
		cmdBuild(),
		cmdBump(),
		cmdBundle(),
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
		cmdUpdate(),
		cmdVEX(),
		cmdWithdraw(),
		version.Version(),
	)

	return cmd
}
