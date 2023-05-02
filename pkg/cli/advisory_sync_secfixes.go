package cli

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory/sync"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	advisoryconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/advisory"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func AdvisorySyncSecfixes() *cobra.Command {
	p := &syncSecfixesParams{}
	cmd := &cobra.Command{
		Use:           "sync-secfixes",
		Short:         "synchronize secfixes and advisories for specific packages or across all of Wolfi",
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			advisoriesRepoDir := resolveAdvisoriesDir(p.advisoriesRepoDir)
			if advisoriesRepoDir == "" {
				advisoriesRepoDir = defaultAdvisoriesRepoDir
			}

			advisoriesFsys := rwos.DirFS(advisoriesRepoDir)
			advisoryCfgs, err := advisoryconfigs.NewIndex(advisoriesFsys)
			if err != nil {
				return err
			}

			var cfgs configs.Selection[advisoryconfigs.Document]
			if pkg := p.packageName; pkg != "" {
				cfgs = advisoryCfgs.Select().WhereName(pkg)
			} else {
				cfgs = advisoryCfgs.Select()
			}

			needs, err := sync.DetermineNeeds(cfgs)
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
				return errors.New("secfixes and advisories are not in sync (to fix this, run `wolfictl advisory sync-secfixes`)")
			}

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type syncSecfixesParams struct {
	advisoriesRepoDir string

	packageName string

	warn bool
}

func (p *syncSecfixesParams) addFlagsTo(cmd *cobra.Command) {
	addAdvisoriesDirFlag(&p.advisoriesRepoDir, cmd)

	addPackageFlag(&p.packageName, cmd)

	cmd.Flags().BoolVar(&p.warn, "warn", false, "don't write changes to files, but exit 1 if there would be changes")
}
