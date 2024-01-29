package cli

import (
	"fmt"
	"log/slog"

	"chainguard.dev/apko/pkg/log"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/version"
)

func New() *cobra.Command {
	var logPolicy []string
	var logLevel string
	cmd := &cobra.Command{
		Use:               "wolfictl",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		Short:             "A CLI helper for developing Wolfi",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var level slog.Level
			switch logLevel {
			case "debug":
				level = slog.LevelDebug
			case "info":
				level = slog.LevelInfo
			case "warn":
				level = slog.LevelWarn
			case "error":
				level = slog.LevelError
			default:
				return fmt.Errorf("invalid log level: %s", logLevel)
			}

			slog.SetDefault(slog.New(log.Handler(logPolicy, level)))

			return nil
		},
	}
	cmd.PersistentFlags().StringSliceVar(&logPolicy, "log-policy", []string{"builtin:stderr"}, "log policy (e.g. builtin:stderr, /tmp/log/foo)")
	cmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level (e.g. debug, info, warn, error)")

	cmd.AddCommand(
		cmdAdvisory(),
		cmdApk(),
		cmdBuild(),
		cmdBump(),
		cmdCheck(),
		cmdGh(),
		cmdImage(),
		cmdIndex(),
		cmdLint(),
		cmdRuby(),
		cmdLs(),
		cmdSVG(),
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
