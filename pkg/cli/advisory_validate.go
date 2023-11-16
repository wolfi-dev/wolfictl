package cli

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
	"github.com/wolfi-dev/wolfictl/pkg/git"
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

It also looks for issues in the _changes_ introduced by the current state of the
advisories repo, relative to a "base state" (such as the last known state of
the upstream repo's main branch). For example, it will detect if an advisory
was removed, which is not allowed.

Using distro auto-detection is the easiest way to run this command. It will
automatically detect the distro you're running, and use the correct advisory
repo URL and base hash to compare against.


If you want to run this command without distro auto-detection, you'll need to
specify the following flags:

* --no-distro-detection
* --advisories-repo-dir
* --advisories-repo-url
* --advisories-repo-base-hash

More information about these flags is shown in the documentation for each flag.

If any issues are found in the advisory data, the command will exit 1, and will 
print an error message that specifies where and how the data is invalid.`,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var advisoriesRepoDir string
			var advisoriesRepoUpstreamHTTPSURL string
			var advisoriesRepoForkPoint string

			if p.doNotDetectDistro {
				if p.advisoriesRepoDir == "" {
					return fmt.Errorf("need --%s when --%s is specified", flagNameAdvisoriesRepoDir, flagNameNoDistroDetection)
				}
				advisoriesRepoDir = p.advisoriesRepoDir

				if p.advisoriesRepoUpstreamHTTPSURL == "" {
					return fmt.Errorf("need --%s when --%s is specified", flagNameAdvisoriesRepoURL, flagNameNoDistroDetection)
				}
				advisoriesRepoUpstreamHTTPSURL = p.advisoriesRepoUpstreamHTTPSURL

				if p.advisoriesRepoBaseHash == "" {
					return fmt.Errorf("need --%s when --%s is specified", flagNameAdvisoriesRepoBaseHash, flagNameNoDistroDetection)
				}
				advisoriesRepoForkPoint = p.advisoriesRepoBaseHash
			} else {
				// Catch any use of flags that get ignored when distro detection is enabled to avoid user confusion.
				switch {
				case p.advisoriesRepoDir != "":
					return fmt.Errorf("using --%s requires --%s", flagNameAdvisoriesRepoDir, flagNameNoDistroDetection)
				case p.advisoriesRepoUpstreamHTTPSURL != "":
					return fmt.Errorf("using --%s requires --%s", flagNameAdvisoriesRepoURL, flagNameNoDistroDetection)
				case p.advisoriesRepoBaseHash != "":
					return fmt.Errorf("using --%s requires --%s", flagNameAdvisoriesRepoBaseHash, flagNameNoDistroDetection)
				}

				d, err := distro.Detect()
				if err != nil {
					return fmt.Errorf("distro auto-detection failed: %w", err)
				}

				fmt.Fprint(os.Stderr, renderDetectedDistro(d))

				advisoriesRepoDir = d.Local.AdvisoriesRepo.Dir
				advisoriesRepoUpstreamHTTPSURL, err = getAdvisoriesHTTPSRemoteURL(d)
				if err != nil {
					return err
				}
				advisoriesRepoForkPoint = d.Local.AdvisoriesRepo.ForkPoint
			}

			cloneDir, err := git.TempClone(
				advisoriesRepoUpstreamHTTPSURL,
				advisoriesRepoForkPoint,
				true,
			)
			defer os.RemoveAll(cloneDir)
			if err != nil {
				return fmt.Errorf("unable to produce a base repo state for comparison: %w", err)
			}

			baseAdvisoriesIndex, err := v2.NewIndex(rwos.DirFS(cloneDir))
			if err != nil {
				return err
			}

			advisoriesIndex, err := v2.NewIndex(rwos.DirFS(advisoriesRepoDir))
			if err != nil {
				return err
			}

			af := advisory.NewHTTPAliasFinder(http.DefaultClient)

			selectedPackageSet := make(map[string]struct{})
			for _, pkg := range p.packages {
				selectedPackageSet[pkg] = struct{}{}
			}

			opts := advisory.ValidateOptions{
				AdvisoryDocs:     advisoriesIndex,
				BaseAdvisoryDocs: baseAdvisoriesIndex,
				SelectedPackages: selectedPackageSet,
				Now:              time.Now(),
				AliasFinder:      af,
			}

			validationErr := advisory.Validate(cmd.Context(), opts)
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
	doNotDetectDistro              bool
	advisoriesRepoDir              string
	advisoriesRepoUpstreamHTTPSURL string
	advisoriesRepoBaseHash         string
	packages                       []string
}

const (
	flagNameAdvisoriesRepoURL      = "advisories-repo-url"
	flagNameAdvisoriesRepoBaseHash = "advisories-repo-base-hash"
)

func (p *validateParams) addFlagsTo(cmd *cobra.Command) {
	addNoDistroDetectionFlag(&p.doNotDetectDistro, cmd)
	addAdvisoriesDirFlag(&p.advisoriesRepoDir, cmd)
	cmd.Flags().StringVar(&p.advisoriesRepoUpstreamHTTPSURL, flagNameAdvisoriesRepoURL, "", "HTTPS URL of the upstream Git remote for the advisories repo")
	cmd.Flags().StringVar(&p.advisoriesRepoBaseHash, flagNameAdvisoriesRepoBaseHash, "", "commit hash of the upstream repo to which the current state will be compared in the diff")
	cmd.Flags().StringSliceVarP(&p.packages, flagNamePackage, "p", nil, "packages to validate")
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

		// Add an extra newline for the top-level errors
		sep := "\n"
		if depth == 0 {
			sep = "\n\n"
		}

		return strings.Join(
			lo.Map(errs, func(err error, _ int) string {
				return renderValidationError(err, depth)
			}),
			sep,
		)
	}

	return fmt.Sprintf("%s%s", indent(depth), err)
}

func indent(depth int) string {
	return strings.Repeat("    ", depth)
}
