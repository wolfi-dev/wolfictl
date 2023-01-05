package cli

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory/sync"
)

func AdvisorySyncSecfixes() *cobra.Command {
	p := &syncSecfixesParams{}
	cmd := &cobra.Command{
		Use:           "sync-secfixes",
		Short:         "synchronize secfixes and advisories for specific packages or across all of Wolfi",
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			index, err := newConfigIndexFromArgs(args...)
			if err != nil {
				return err
			}

			needs, err := sync.NeedsFromIndex(index)
			if err != nil {
				return err
			}

			syncNeeded := false
			for _, need := range needs {
				if need.Met() {
					continue
				}
				syncNeeded = true

				if p.warn {
					fmt.Printf("%s\n", need)
					continue
				}

				err := need.Resolve()
				if err != nil {
					return fmt.Errorf("unable to sync: %w", err)
				}
			}

			if p.warn && syncNeeded {
				return errors.New("secfixes and advisories are not in sync")
			}

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type syncSecfixesParams struct {
	warn bool
}

func (p *syncSecfixesParams) addFlagsTo(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&p.warn, "warn", false, "don't write changes to files, but exit 1 if there would be changes")
}
