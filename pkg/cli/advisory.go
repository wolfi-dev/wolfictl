package cli

import (
	"fmt"
	"log"
	"time"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory/sync"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	rwfsOS "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
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
	cmd.AddCommand(AdvisoryDiscover())

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

func newConfigIndexFromArgs(args ...string) (*configs.Index, error) {
	if len(args) == 0 {
		// parse all configurations in the current directory
		i, err := configs.NewIndex(rwfsOS.DirFS("."))
		if err != nil {
			return nil, fmt.Errorf("unable to index Wolfi package configurations: %w", err)
		}
		return i, nil
	}

	i, err := configs.NewIndexFromPaths(".", args...)
	if err != nil {
		return nil, fmt.Errorf("unable to index Wolfi package configurations: %w", err)
	}
	return i, nil
}

func doFollowupSync(index *configs.Index) error {
	needs, err := sync.NeedsFromIndex(index)
	if err != nil {
		return fmt.Errorf("unable to sync secfixes data for advisory: %w", err)
	}

	unmetNeeds := sync.Unmet(needs)

	if len(unmetNeeds) == 0 {
		log.Printf("INFO: No secfixes data needed to be added from this advisory. Secfixes data is in sync. 👍")
		return nil
	}

	for _, n := range unmetNeeds {
		err := n.Resolve()
		if err != nil {
			return fmt.Errorf("unable to sync secfixes data for advisory: %w", err)
		}
	}

	return nil
}
