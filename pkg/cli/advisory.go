package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
)

func Advisory() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "advisory",
		SilenceErrors: true,
		Short:         "Utilities for viewing and modifying Wolfi advisory data",
	}

	cmd.AddCommand(AdvisoryList())
	cmd.AddCommand(AdvisoryCreate())
	cmd.AddCommand(AdvisoryUpdate())
	cmd.AddCommand(AdvisorySyncSecfixes())

	return cmd
}

func resolveTimestamp(ts string) (time.Time, error) {
	if ts == "now" {
		return time.Now(), nil
	}

	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return time.Time{}, fmt.Errorf("unable to parse timestamp: %w", err)
	}

	return t, nil
}

func argsToConfigs(args []string) (*configs.Index, error) {
	if len(args) == 0 {
		// parse all configurations in the current directory
		i, err := configs.NewIndex(os.DirFS("."))
		if err != nil {
			return nil, fmt.Errorf("unable to index Wolfi package configurations: %w", err)
		}
		return i, nil
	}

	i, err := configs.NewIndexFromPaths(args...)
	if err != nil {
		return nil, fmt.Errorf("unable to index Wolfi package configurations: %w", err)
	}
	return i, nil
}
