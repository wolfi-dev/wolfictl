package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/osv-scanner/pkg/models"
	"github.com/spf13/cobra"

	"github.com/chainguard-dev/clog"

	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
)

func cmdAdvisoryExport() *cobra.Command {
	p := &exportParams{}
	cmd := &cobra.Command{
		Use:           "export",
		Short:         "Export advisory data (experimental)",
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		Hidden:        true,

		PreRunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			if p.format == OutputOSV {
				if _, err := os.Stat(p.outputLocation); os.IsNotExist(err) {
					clog.FromContext(ctx).Errorf("directory %s does not exist, please create that first", p.outputLocation)
					return err
				}
			}

			return nil
		},

		RunE: func(cmd *cobra.Command, _ []string) error {
			if len(p.advisoriesRepoDirs) == 0 {
				if p.doNotDetectDistro {
					return fmt.Errorf("no advisories repo dir specified")
				}

				d, err := distro.Detect()
				if err != nil {
					return fmt.Errorf("no advisories repo dir specified, and distro auto-detection failed: %w", err)
				}

				p.advisoriesRepoDirs = append(p.advisoriesRepoDirs, d.Local.AdvisoriesRepo.Dir)
				_, _ = fmt.Fprint(os.Stderr, renderDetectedDistro(d))
			}

			indices := make([]*configs.Index[v2.Document], 0, len(p.advisoriesRepoDirs))
			for _, dir := range p.advisoriesRepoDirs {
				advisoryFsys := rwos.DirFS(dir)
				index, err := v2.NewIndex(cmd.Context(), advisoryFsys)
				if err != nil {
					return fmt.Errorf("unable to index advisory configs for directory %q: %w", dir, err)
				}

				indices = append(indices, index)
			}

			opts := advisory.ExportOptions{
				AdvisoryDocIndices: indices,
				Ecosystem:          models.Ecosystem(p.ecosystem),
			}

			var export io.Reader
			var err error
			switch p.format {
			case OutputYAML:
				export, err = advisory.ExportYAML(opts)
			case OutputCSV:
				export, err = advisory.ExportCSV(opts)
			case OutputOSV:
				err = advisory.ExportOSV(opts, p.outputLocation)
			default:
				return fmt.Errorf("unrecognized format: %q. Valid formats are: [%s]", p.format, strings.Join([]string{OutputYAML, OutputCSV, OutputOSV}, ", "))
			}
			if err != nil {
				return fmt.Errorf("unable to export advisory data: %w", err)
			}

			if p.format != OutputOSV {
				var outputFile *os.File
				if p.outputLocation == "" {
					outputFile = os.Stdout
				} else {
					outputFile, err = os.Create(p.outputLocation)
					if err != nil {
						return fmt.Errorf("unable to create output file: %w", err)
					}
					defer outputFile.Close()
				}

				_, err = io.Copy(outputFile, export)
				if err != nil {
					return fmt.Errorf("unable to export data to specified location: %w", err)
				}
			}

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type exportParams struct {
	doNotDetectDistro  bool
	advisoriesRepoDirs []string
	outputLocation     string
	// format controls how commands will produce their output.
	format    string
	ecosystem string
}

const (
	// OutputYAML YAML output.
	OutputYAML = "yaml"
	// OutputCSV CSV output.
	OutputCSV = "csv"
	// OutputOSV OSV output.
	OutputOSV = "osv"
)

func (p *exportParams) addFlagsTo(cmd *cobra.Command) {
	addNoDistroDetectionFlag(&p.doNotDetectDistro, cmd)

	cmd.Flags().StringSliceVarP(&p.advisoriesRepoDirs, "advisories-repo-dir", "a", nil, "directory containing an advisories repository")
	cmd.Flags().StringVarP(&p.outputLocation, "output", "o", "", "output location (default: stdout). In case using OSV format this will be the output directory.")
	cmd.Flags().StringVarP(&p.format, "format", "f", OutputCSV, fmt.Sprintf("Output format. One of: [%s]", strings.Join([]string{OutputYAML, OutputCSV, OutputOSV}, ", ")))
	cmd.Flags().StringVarP(&p.ecosystem, "ecosystem", "e", "wolfi", fmt.Sprintf("Ecosystem format. One of: [%s]", strings.Join([]string{"wolfi", "chainguard"}, ", ")))
}
