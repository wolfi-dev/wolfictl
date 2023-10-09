package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
)

func cmdAdvisorySecDB() *cobra.Command {
	p := &dbParams{}
	cmd := &cobra.Command{
		Use:           "secdb",
		Aliases:       []string{"db"},
		Short:         "Build a security database from advisory data",
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(p.advisoriesRepoDirs) == 0 {
				if p.doNotDetectDistro {
					return fmt.Errorf("no advisories repo dir specified")
				}

				d, err := distro.Detect()
				if err != nil {
					return fmt.Errorf("no advisories repo dir specified, and distro auto-detection failed: %w", err)
				}

				p.advisoriesRepoDirs = append(p.advisoriesRepoDirs, d.AdvisoriesRepoDir)
				_, _ = fmt.Fprint(os.Stderr, renderDetectedDistro(d))
			}

			indices := make([]*configs.Index[v2.Document], 0, len(p.advisoriesRepoDirs))
			for _, dir := range p.advisoriesRepoDirs {
				advisoryFsys := rwos.DirFS(dir)
				index, err := v2.NewIndex(advisoryFsys)
				if err != nil {
					return fmt.Errorf("unable to index advisory configs for directory %q: %w", dir, err)
				}

				indices = append(indices, index)
			}

			opts := advisory.BuildSecurityDatabaseOptions{
				AdvisoryDocIndices: indices,
				URLPrefix:          p.urlPrefix,
				Archs:              p.archs,
				Repo:               p.repo,
			}

			database, err := advisory.BuildSecurityDatabase(opts)
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
	doNotDetectDistro bool

	advisoriesRepoDirs []string

	outputLocation string

	urlPrefix string
	archs     []string
	repo      string
}

func (p *dbParams) addFlagsTo(cmd *cobra.Command) {
	addNoDistroDetectionFlag(&p.doNotDetectDistro, cmd)

	cmd.Flags().StringSliceVarP(&p.advisoriesRepoDirs, "advisories-repo-dir", "a", nil, "directory containing an advisories repository")

	cmd.Flags().StringVarP(&p.outputLocation, "output", "o", "", "output location (default: stdout)")

	cmd.Flags().StringVar(&p.urlPrefix, "url-prefix", "https://packages.wolfi.dev", "URL scheme and hostname for the package repository")
	cmd.Flags().StringSliceVar(&p.archs, "arch", []string{"x86_64"}, "the package architectures the security database is for")
	cmd.Flags().StringVar(&p.repo, "repo", "os", "the name of the package repository")
}
