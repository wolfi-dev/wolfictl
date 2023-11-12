package cli

import (
	"fmt"
	"os"
	"strings"

	"chainguard.dev/melange/pkg/config"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	buildconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/build"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
	"github.com/wolfi-dev/wolfictl/pkg/ls"
)

func cmdLs() *cobra.Command {
	p := &lsParams{}
	cmd := &cobra.Command{
		Use:           "ls [packages]",
		Short:         "List distro packages (experimental)",
		SilenceErrors: true,
		Hidden:        true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(p.distroRepoDirs) == 0 {
				if p.doNotDetectDistro {
					return fmt.Errorf("no distro repo dir specified")
				}

				d, err := distro.Detect()
				if err != nil {
					return fmt.Errorf("no distro repo dir specified, and distro auto-detection failed: %w", err)
				}

				p.distroRepoDirs = append(p.distroRepoDirs, d.Local.PackagesRepo.Dir)
				_, _ = fmt.Fprint(os.Stderr, renderDetectedDistro(d))
			}

			indices := make([]*configs.Index[config.Configuration], 0, len(p.distroRepoDirs))
			for _, dir := range p.distroRepoDirs {
				distroFsys := rwos.DirFS(dir)
				index, err := buildconfigs.NewIndex(distroFsys)
				if err != nil {
					return fmt.Errorf("unable to index build configs for directory %q: %w", dir, err)
				}

				indices = append(indices, index)
			}

			requestedPkgs := args

			opts := ls.ListOptions{
				BuildCfgIndices:    indices,
				IncludeSubpackages: p.includeSubpackages,
				RequestedPackages:  requestedPkgs,
				Template:           p.format,
			}

			results, err := ls.List(opts)
			if err != nil {
				return fmt.Errorf("unable to list packages: %w", err)
			}

			fmt.Println(strings.Join(results, "\n"))

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type lsParams struct {
	doNotDetectDistro bool
	distroRepoDirs    []string

	includeSubpackages bool
	format             string
}

func (p *lsParams) addFlagsTo(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&p.doNotDetectDistro, "do-not-detect-distro", false, "Do not auto-detect distro")
	cmd.Flags().StringSliceVarP(&p.distroRepoDirs, "distro-repo-dir", "d", nil, "Path to distro repo dir")

	cmd.Flags().BoolVarP(&p.includeSubpackages, "subpackages", "s", false, "Include subpackages")
	cmd.Flags().StringVarP(&p.format, "format", "f", "", "Output format (in the form of a literal Go template applied to each result item)")
}
