package cli

import (
	"fmt"

	"chainguard.dev/melange/pkg/config"
	v2 "github.com/chainguard-dev/advisory-schema/pkg/advisory/v2"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	adv2 "github.com/wolfi-dev/wolfictl/pkg/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	"github.com/wolfi-dev/wolfictl/pkg/configs/build"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func cmdAdvisoryOSV() *cobra.Command {
	p := &osvParams{}
	cmd := &cobra.Command{
		Use:   "osv",
		Short: "Build an OSV dataset from Chainguard advisory data",
		Long: `Build an OSV dataset from Chainguard advisory data.

This command reads advisory data from one or more directories containing Chainguard
advisory documents, and writes an OSV dataset to a local directory.

Specify directories for advisory repositories using the --advisories-repo-dir flag.

IMPORTANT: For now, the command assumes that the first listed advisory repository is the
"Wolfi" repository, and that the rest are not. In the future, we might unify all advisory
repositories into a single collection of all advisory documents, and remove the need for
multiple advisory repositories.

The user must also specify directories for all package repositories associated with the
given advisory data. This is used to make sure the OSV data includes all relevant packages
and subpackages.

The output directory for the OSV dataset is specified using the --output flag. This
directory must already exist before running the command.
`,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			if len(p.advisoriesRepoDirs) == 0 {
				return fmt.Errorf("at least one advisory repository directory must be specified")
			}

			if len(p.packagesRepoDirs) == 0 {
				return fmt.Errorf("at least one package repository directory must be specified")
			}

			if p.outputDirectory == "" {
				return fmt.Errorf("output directory must be specified")
			}

			advisoryIndices := make([]*configs.Index[v2.Document], 0, len(p.advisoriesRepoDirs))
			for _, dir := range p.advisoriesRepoDirs {
				fsys := rwos.DirFS(dir)
				index, err := adv2.NewIndex(cmd.Context(), fsys)
				if err != nil {
					return fmt.Errorf("indexing advisory documents for directory %q: %w", dir, err)
				}

				advisoryIndices = append(advisoryIndices, index)
			}

			packageIndices := make([]*configs.Index[config.Configuration], 0, len(p.packagesRepoDirs))
			for _, dir := range p.packagesRepoDirs {
				fsys := rwos.DirFS(dir)
				index, err := build.NewIndex(cmd.Context(), fsys)
				if err != nil {
					return fmt.Errorf("indexing package build configurations for directory %q: %w", dir, err)
				}

				packageIndices = append(packageIndices, index)
			}

			addedEcosystems := []string{"Wolfi"}
			for i := range p.advisoriesRepoDirs {
				if i == 0 {
					// Skip the first advisory repository, which is the "Wolfi" repository.
					continue
				}
				addedEcosystems = append(addedEcosystems, "")
			}

			opts := advisory.OSVOptions{
				AdvisoryDocIndices:   advisoryIndices,
				PackageConfigIndices: packageIndices,
				AddedEcosystems:      addedEcosystems,
				OutputDirectory:      p.outputDirectory,
			}

			err := advisory.BuildOSVDataset(ctx, opts)
			if err != nil {
				return fmt.Errorf("building OSV dataset: %w", err)
			}

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type osvParams struct {
	advisoriesRepoDirs []string
	packagesRepoDirs   []string
	outputDirectory    string
}

func (p *osvParams) addFlagsTo(cmd *cobra.Command) {
	cmd.Flags().StringSliceVarP(&p.advisoriesRepoDirs, "advisories-repo-dir", "a", nil, "path to the directory(ies) containing Chainguard advisory data")
	cmd.Flags().StringSliceVarP(&p.packagesRepoDirs, "packages-repo-dir", "p", nil, "path to the directory(ies) containing Chainguard package data")
	cmd.Flags().StringVarP(&p.outputDirectory, "output", "o", "", "path to a local directory in which the OSV dataset will be written")
}
