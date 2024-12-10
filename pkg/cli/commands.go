package cli

import (
	"fmt"
	"log/slog"
	"math"
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
			// Ensure level is within the int32 range
			if int(level) < math.MinInt32 || int(level) > math.MaxInt32 {
				return fmt.Errorf("log level out of range: %d", level)
			}

			// TODO: This is done to ensure no overflows, but remove this nonsense once
			//  charmlog.Level uses the same type as slog.Level. See
			//  https://github.com/charmbracelet/log/pull/141.

			l := charmlog.Level(level) //nolint:gosec // level is checked above
			slog.SetDefault(slog.New(charmlog.NewWithOptions(os.Stderr, charmlog.Options{ReportTimestamp: true, Level: l})))
			return nil
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
