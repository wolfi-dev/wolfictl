package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func cmdAdvisoryOSV() *cobra.Command {
	p := &osvParams{}
	cmd := &cobra.Command{
		Use:           "osv",
		Short:         "Build an OSV dataset from Chainguard advisory data",
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			if len(p.advisoriesRepoDirs) == 0 {
				p.advisoriesRepoDirs = append(p.advisoriesRepoDirs, ".")
			}

			indices := make([]*configs.Index[v2.Document], 0, len(p.advisoriesRepoDirs))
			for _, dir := range p.advisoriesRepoDirs {
				advisoryFsys := rwos.DirFS(dir)
				index, err := v2.NewIndex(cmd.Context(), advisoryFsys)
				if err != nil {
					return fmt.Errorf("indexing advisory documents for directory %q: %w", dir, err)
				}

				indices = append(indices, index)
			}

			opts := advisory.OSVOptions{
				AdvisoryDocIndices: indices,
				OutputDirectory:    p.outputDirectory,
				Ecosystem:          advisory.OSVEcosystem,
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
	outputDirectory    string
}

func (p *osvParams) addFlagsTo(cmd *cobra.Command) {
	cmd.Flags().StringSliceVarP(&p.advisoriesRepoDirs, "advisories-repo-dir", "a", nil, "path to the directory(ies) containing Chainguard advisory data (default: current directory)")
	cmd.Flags().StringVarP(&p.outputDirectory, "output", "o", "", "path to a local directory in which the OSV dataset will be written")
}
