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
		Short:         "Build a security database from advisory data (NOTE: For now, this command uses secfixes data, but will soon use advisory data instead.)",
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
				URLPrefix:    p.urlPrefix,
				Archs:        p.archs,
				Repo:         p.repo,
			}

			database, err := advisory.BuildDatabase(opts)
			if err != nil {
				return err
			}

			var outputFile *os.File
			if p.outputLocation == "" {
				outputFile = os.Stdout
			} else {
				outputFile, err = os.Create(p.outputLocation)
				if err != nil {
					return fmt.Errorf("unable to open output file: %w", err)
				}
				defer outputFile.Close()
			}

			_, err = outputFile.Write(database)
			if err != nil {
				return fmt.Errorf("unable to write the security database to specified location: %w", err)
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

	urlPrefix string
	archs     []string
	repo      string
}

func (p *dbParams) addFlagsTo(cmd *cobra.Command) {
	addAdvisoriesDirFlag(&p.advisoriesRepoDir, cmd)

	cmd.Flags().StringVarP(&p.outputLocation, "output", "o", "", "output location (default: stdout)")

	cmd.Flags().StringVar(&p.urlPrefix, "url-prefix", "https://packages.wolfi.dev", "URL scheme and hostname for the package repository")
	cmd.Flags().StringSliceVar(&p.archs, "arch", []string{"x86_64"}, "the package architectures the security database is for")
	cmd.Flags().StringVar(&p.repo, "repo", "os", "the name of the package repository")
}
