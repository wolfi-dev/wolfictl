package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/configs/build"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/scan"
)

func cmdScanSource() *cobra.Command {
	p := &scanSourceParams{}
	cmd := &cobra.Command{
		Use:           "scan-source",
		Short:         "Scan a package's source code for vulnerabilities",
		Args:          cobra.MinimumNArgs(1),
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := newLogger(p.verbosity)

			distroDir := p.distroDir
			if distroDir == "" {
				distroDir = "."
			}

			fsys := rwos.DirFS(distroDir)
			index, err := build.NewIndex(fsys)
			if err != nil {
				return fmt.Errorf("failed to create index of package configurations: %w", err)
			}

			first, err := index.Select().WhereName(args[0]).First()
			if err != nil {
				return fmt.Errorf("failed to find configuration for package %q: %w", args[0], err)
			}
			cfg := first.Configuration()

			logger.Info("scanning source code used in melange configuration", "package", cfg.Name())

			scanResults, err := scan.Sources(cmd.Context(), logger, cfg)
			if err != nil {
				return fmt.Errorf("failed to scan sources for %q: %w", cfg.Name(), err)
			}

			for _, r := range scanResults {
				fmt.Print(r)
			}

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type scanSourceParams struct {
	distroDir string
	verbosity int
}

func (p *scanSourceParams) addFlagsTo(cmd *cobra.Command) {
	addDistroDirFlag(&p.distroDir, cmd)
	addVerboseFlag(&p.verbosity, cmd)
}
