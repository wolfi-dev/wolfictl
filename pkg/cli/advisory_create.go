package cli

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/apk/client"
	"chainguard.dev/melange/pkg/config"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/advisory/prompt"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	buildconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/build"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
)

func cmdAdvisoryCreate() *cobra.Command {
	p := &createParams{}
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new advisory",
		Long: `Create a new advisory.

Use this command to create a new advisory, i.e. when the given
package/vulnerability combination doesn't already exist in the advisories repo.
If the package/vulnerability combination already exists, use the "update"
command instead.

This command will prompt for all required fields, and will attempt to fill in
as many optional fields as possible. You can abort the advisory creation at any
point in the prompt by pressing Ctrl+C.

You can specify required values on the command line using the flags relevant to
the advisory you are creating. If not all required values are provided on the
command line, the command will prompt for the missing values.

If the --no-prompt flag is specified, then the command will fail if any
required fields are missing.

This command also performs a follow-up operation to discover aliases for the
newly created advisory and any other advisories for the same package.`,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Get initial values for distro-related parameters.
			archs := p.archs
			packageRepositoryURL := p.packageRepositoryURL
			distroRepoDir := resolveDistroDir(p.distroRepoDir)
			advisoriesRepoDir := resolveAdvisoriesDirInput(p.advisoriesRepoDir)

			// If we're not using auto-detection, we need to fail fast on any missing
			// parameter values.
			if p.doNotDetectDistro {
				var missingParamWarnings []string

				if distroRepoDir == "" {
					missingParamWarnings = append(missingParamWarnings, fmt.Sprintf("  - distro repository directory (specify using --%s)", flagNameDistroRepoDir))
				}
				if advisoriesRepoDir == "" {
					missingParamWarnings = append(missingParamWarnings, fmt.Sprintf("  - advisories repository directory (specify using --%s)", flagNameAdvisoriesRepoDir))
				}
				if packageRepositoryURL == "" {
					missingParamWarnings = append(missingParamWarnings, fmt.Sprintf("  - package repository URL (specify using --%s)", flagNamePackageRepoURL))
				}
				if len(missingParamWarnings) > 0 {
					return fmt.Errorf(
						"one or more distro configuration values was left unspecified and couldn't be automatically resolved because distro auto-detection was disabled by user:\n%v",
						strings.Join(missingParamWarnings, "\n"),
					)
				}
			}

			// If we made it this far, we either have all the values, or we'll be able to
			// use auto-detection to resolve the rest.

			if distroRepoDir == "" || advisoriesRepoDir == "" || packageRepositoryURL == "" {
				d, err := distro.Detect()
				if err != nil {
					return fmt.Errorf("distro repo dir and/or advisories repo dir was left unspecified, and distro auto-detection failed: %w", err)
				}

				// Replace only the values that are still empty.

				if len(archs) == 0 {
					archs = d.Absolute.SupportedArchitectures
				}

				if packageRepositoryURL == "" {
					packageRepositoryURL = d.Absolute.APKRepositoryURL
				}

				if distroRepoDir == "" {
					distroRepoDir = d.Local.PackagesRepo.Dir
				}

				if advisoriesRepoDir == "" {
					advisoriesRepoDir = d.Local.AdvisoriesRepo.Dir
				}

				_, _ = fmt.Fprint(os.Stderr, renderDetectedDistro(d))
			}

			advisoryFsys := rwos.DirFS(advisoriesRepoDir)
			advisoryCfgs, err := v2.NewIndex(cmd.Context(), advisoryFsys)
			if err != nil {
				return err
			}

			fsys := rwos.DirFS(distroRepoDir)
			buildCfgs, err := buildconfigs.NewIndex(cmd.Context(), fsys)
			if err != nil {
				return fmt.Errorf("unable to select packages: %w", err)
			}

			req, err := p.requestParams.advisoryRequest()
			if err != nil {
				return err
			}

			if req.AdvisoryID != "" {
				return fmt.Errorf("cannot create advisory: %q is an advisory ID, which the user is not allowed to assign", req.AdvisoryID)
			}

			c := client.New(http.DefaultClient)
			var apkindexes []*apk.APKIndex
			for _, arch := range archs {
				idx, err := c.GetRemoteIndex(cmd.Context(), packageRepositoryURL, arch)
				if err != nil {
					return fmt.Errorf("getting APKINDEX for %s: %w", arch, err)
				}
				apkindexes = append(apkindexes, idx)
			}

			var noAliasesErr error
			if len(req.Aliases) == 0 {
				noAliasesErr = fmt.Errorf("at least one alias (non-CGA vulnerability ID) is required")
			}

			if err := errors.Join(req.Validate(), noAliasesErr); err != nil {
				if p.doNotPrompt {
					return fmt.Errorf("not enough information to create advisory: %w", err)
				}

				// prompt for missing fields

				allowedPackages := func() []string {
					return lo.Map(buildCfgs.Select().Configurations(), func(cfg config.Configuration, _ int) string {
						return cfg.Package.Name
					})
				}

				allowedVulnerabilities := func(_ string) []string {
					return nil
				}

				allowedFixedVersions := newAllowedFixedVersionsFunc(apkindexes, buildCfgs)

				m := prompt.New(prompt.Configuration{
					Request:                    req,
					AllowedPackagesFunc:        allowedPackages,
					AllowedVulnerabilitiesFunc: allowedVulnerabilities,
					AllowedFixedVersionsFunc:   allowedFixedVersions,
				})
				var returnedModel tea.Model
				program := tea.NewProgram(m)

				if returnedModel, err = program.Run(); err != nil {
					return err
				}

				if m, ok := returnedModel.(prompt.Model); ok {
					if m.EarlyExit {
						return nil
					}

					req = m.Request
				} else {
					return fmt.Errorf("unexpected model type: %T", returnedModel)
				}
			}

			opts := advisory.CreateOptions{
				AdvisoryDocs: advisoryCfgs,
			}

			err = advisory.Create(cmd.Context(), req, opts)
			if err != nil {
				return fmt.Errorf("unable to create advisory: %w", err)
			}

			err = advisory.DiscoverAliases(cmd.Context(), advisory.DiscoverAliasesOptions{
				AdvisoryDocs:     opts.AdvisoryDocs,
				AliasFinder:      advisory.NewHTTPAliasFinder(http.DefaultClient),
				SelectedPackages: map[string]struct{}{req.Package: {}},
			})
			if err != nil {
				return fmt.Errorf("unable to discover aliases for newly created advisory: %w", err)
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

	requestParams                    advisoryRequestParams
	distroRepoDir, advisoriesRepoDir string
	archs                            []string
	packageRepositoryURL             string
}

func (p *createParams) addFlagsTo(cmd *cobra.Command) {
	addNoDistroDetectionFlag(&p.doNotDetectDistro, cmd)
	addNoPromptFlag(&p.doNotPrompt, cmd)

	p.requestParams.addFlags(cmd)
	addDistroDirFlag(&p.distroRepoDir, cmd)
	addAdvisoriesDirFlag(&p.advisoriesRepoDir, cmd)
	cmd.Flags().StringSliceVar(&p.archs, "arch", []string{"x86_64", "aarch64"}, "package architectures to find published versions for")
	addPackageRepoURLFlag(&p.packageRepositoryURL, cmd)
}
