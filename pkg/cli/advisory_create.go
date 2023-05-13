//nolint:dupl // We expect create and update to diverge.
package cli

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/advisory/createprompt"
	advisoryconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/advisory"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
)

func AdvisoryCreate() *cobra.Command {
	p := &createParams{}
	cmd := &cobra.Command{
		Use:           "create",
		Short:         "create a new advisory for a package",
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			advisoriesRepoDir := resolveAdvisoriesDir(p.advisoriesRepoDir)
			if advisoriesRepoDir == "" {
				if p.doNotDetectDistro {
					return fmt.Errorf("no advisories repo dir specified")
				}

				d, err := distro.Detect()
				if err != nil {
					return fmt.Errorf("no advisories repo dir specified, and distro auto-detection failed: %w", err)
				}

				advisoriesRepoDir = d.AdvisoriesRepoDir
				_, _ = fmt.Fprint(os.Stderr, renderDetectedDistro(d))
			}

			advisoryFsys := rwos.DirFS(advisoriesRepoDir)
			advisoryCfgs, err := advisoryconfigs.NewIndex(advisoryFsys)
			if err != nil {
				return err
			}

			req, err := p.requestParams.advisoryRequest()
			if err != nil {
				return err
			}

			if err := req.Validate(); err != nil {
				if p.doNotPrompt {
					return fmt.Errorf("not enough information to create advisory: %w", err)
				}

				// prompt for missing fields

				m := createprompt.New(req)
				var returnedModel tea.Model
				program := tea.NewProgram(m)

				// try to be helpful: if we're prompting, automatically enable secfixes sync
				p.requestParams.sync = true

				if returnedModel, err = program.Run(); err != nil {
					return err
				}

				if m, ok := returnedModel.(createprompt.Model); ok {
					if m.EarlyExit {
						return nil
					}

					req = m.Request
				} else {
					return fmt.Errorf("unexpected model type: %T", returnedModel)
				}
			}

			opts := advisory.CreateOptions{
				AdvisoryCfgs: advisoryCfgs,
			}

			err = advisory.Create(req, opts)
			if err != nil {
				return err
			}

			if p.requestParams.sync {
				err := doFollowupSync(advisoryCfgs.Select().WhereName(req.Package))
				if err != nil {
					return err
				}
			}

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type createParams struct {
	doNotDetectDistro bool
	doNotPrompt       bool

	requestParams     advisoryRequestParams
	advisoriesRepoDir string
}

func (p *createParams) addFlagsTo(cmd *cobra.Command) {
	addNoDistroDetectionFlag(&p.doNotDetectDistro, cmd)
	addNoPromptFlag(&p.doNotPrompt, cmd)

	p.requestParams.addFlags(cmd)
	addAdvisoriesDirFlag(&p.advisoriesRepoDir, cmd)
}
