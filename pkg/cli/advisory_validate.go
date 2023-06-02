package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	advisoryconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/advisory"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
)

func AdvisoryValidate() *cobra.Command {
	p := &validateParams{}
	cmd := &cobra.Command{
		Use:           "validate",
		Short:         "Validate the state of advisory data",
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			advisoriesRepoDir := resolveAdvisoriesDir(p.advisoriesRepoDir)
			if advisoriesRepoDir == "" {
				if p.doNotDetectDistro {
					return fmt.Errorf("advisories repo dir was left unspecified")
				}

				d, err := distro.Detect()
				if err != nil {
					return fmt.Errorf("advisories repo dir was left unspecified, and distro auto-detection failed: %w", err)
				}

				advisoriesRepoDir = d.AdvisoriesRepoDir
				_, _ = fmt.Fprint(os.Stderr, renderDetectedDistro(d))
			}

			advisoryFsys := rwos.DirFS(advisoriesRepoDir)
			advisoryCfgs, err := advisoryconfigs.NewIndex(advisoryFsys)
			if err != nil {
				return err
			}

			opts := advisory.ValidateOptions{
				AdvisoryCfgs: advisoryCfgs,
			}

			validationErr := advisory.Validate(opts)
			if validationErr != nil {
				fmt.Fprintf(os.Stderr, "❌ advisory data is not valid.%s\n", validationErr)
				os.Exit(1)
			}

			fmt.Fprint(os.Stderr, "✅ advisory data is valid.\n")

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type validateParams struct {
	doNotDetectDistro bool
	advisoriesRepoDir string
}

func (p *validateParams) addFlagsTo(cmd *cobra.Command) {
	addNoDistroDetectionFlag(&p.doNotDetectDistro, cmd)
	addAdvisoriesDirFlag(&p.advisoriesRepoDir, cmd)
}
