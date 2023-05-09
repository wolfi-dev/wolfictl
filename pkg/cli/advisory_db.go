package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	advisoryconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/advisory"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func AdvisoryDB() *cobra.Command {
	p := &dbParams{}
	cmd := &cobra.Command{
		Use:           "db",
		Short:         "Build a security database from advisory data",
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			advisoriesRepoDir := resolveAdvisoriesDir(p.advisoriesRepoDir)
			if advisoriesRepoDir == "" {
				advisoriesRepoDir = defaultAdvisoriesRepoDir
			}

			advisoryFsys := rwos.DirFS(advisoriesRepoDir)
			advisoryCfgs, err := advisoryconfigs.NewIndex(advisoryFsys)
			if err != nil {
				return err
			}

			opts := advisory.BuildDatabaseOptions{
				AdvisoryCfgs: advisoryCfgs,
			}

			database, err := advisory.BuildDatabase(opts)
			if err != nil {
				return err
			}

			_, err = fmt.Fprint(os.Stdout, database)
			if err != nil {
				return fmt.Errorf("unable to write out database: %w", err)
			}

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type dbParams struct {
	advisoriesRepoDir string

	outputLocation string
}

func (p *dbParams) addFlagsTo(cmd *cobra.Command) {
	addAdvisoriesDirFlag(&p.advisoriesRepoDir, cmd)

	cmd.Flags().StringVarP(&p.outputLocation, "output", "o", "", "output location (default: stdout)")
}
