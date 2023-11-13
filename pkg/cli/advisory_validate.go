package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
)

func cmdAdvisoryValidate() *cobra.Command {
	p := &validateParams{}
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate the state of advisory data",
		Long: `Validate the state of the advisory data.

This command examines all advisory documents to check the validity of the data. 

It looks for issues like:

* Missing required fields
* Extra fields
* Enum fields with an unrecognized value
* Basic business logic checks

If any issues are found in the advisory data, the command will exit 1, and will 
print an error message that specifies where and how the data is invalid.`,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			advisoriesRepoDir := resolveAdvisoriesDirInput(p.advisoriesRepoDir)
			if advisoriesRepoDir == "" {
				if p.doNotDetectDistro {
					return fmt.Errorf("advisories repo dir was left unspecified")
				}

				d, err := distro.Detect()
				if err != nil {
					return fmt.Errorf("advisories repo dir was left unspecified, and distro auto-detection failed: %w", err)
				}

				advisoriesRepoDir = d.Local.AdvisoriesRepoDir
				_, _ = fmt.Fprint(os.Stderr, renderDetectedDistro(d))
			}

			advisoryFsys := rwos.DirFS(advisoriesRepoDir)
			advisoryCfgs, err := v2.NewIndex(advisoryFsys)
			if err != nil {
				return err
			}

			opts := advisory.ValidateOptions{
				AdvisoryCfgs: advisoryCfgs,
			}

			validationErr := advisory.Validate(opts)
			if validationErr != nil {
				fmt.Fprintf(
					os.Stderr,
					"❌ advisory data is not valid.\n\n%s\n",
					renderValidationError(validationErr, 0),
				)
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

func renderValidationError(err error, depth int) string {
	if err == nil {
		return ""
	}

	switch e := err.(type) {
	case interface {
		Label() string
		Unwrap() error
	}:
		return fmt.Sprintf("%s%s:\n%s", indent(depth), e.Label(), renderValidationError(e.Unwrap(), depth+1))

	case interface{ Unwrap() []error }:
		errs := e.Unwrap()

		return strings.Join(
			lo.Map(errs, func(err error, _ int) string {
				return renderValidationError(err, depth)
			}),
			"\n",
		)
	}

	return fmt.Sprintf("%s%s", indent(depth), err)
}

func indent(depth int) string {
	return strings.Repeat("  ", depth)
}
