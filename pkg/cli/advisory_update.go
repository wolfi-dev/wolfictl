package cli

import (
	"fmt"
	"os"
	"sort"

	"github.com/chainguard-dev/go-apk/pkg/apk"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/advisory/prompt"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	buildconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/build"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
	"github.com/wolfi-dev/wolfictl/pkg/index"
)

func cmdAdvisoryUpdate() *cobra.Command {
	p := &updateParams{}
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update an existing advisory with a new event",
		Long: `Update an existing advisory with a new event.

Use this command to update an existing advisory by adding a new "event" to the
advisory, i.e. when the given package/vulnerability combination already exists
in the advisories repo. If the package/vulnerability combination doesn't yet
exist, use the "create" command instead.

This command will prompt for all required fields, and will attempt to fill in
as many optional fields as possible. You can abort the advisory update at any
point in the prompt by pressing Ctrl+C.

You can specify required values on the command line using the flags relevant to
the advisory event you are adding. If not all required values are provided on
the command line, the command will prompt for the missing values.

If the --no-prompt flag is specified, then the command will fail if any
required fields are missing.`,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			archs := p.archs
			packageRepositoryURL := p.packageRepositoryURL
			distroRepoDir := resolveDistroDir(p.distroRepoDir)
			advisoriesRepoDir := resolveAdvisoriesDirInput(p.advisoriesRepoDir)
			if distroRepoDir == "" || advisoriesRepoDir == "" {
				if p.doNotDetectDistro {
					return fmt.Errorf("distro repo dir and/or advisories repo dir was left unspecified")
				}

				d, err := distro.Detect()
				if err != nil {
					return fmt.Errorf("distro repo dir and/or advisories repo dir was left unspecified, and distro auto-detection failed: %w", err)
				}

				if len(archs) == 0 {
					archs = d.Absolute.SupportedArchitectures
				}

				if packageRepositoryURL == "" {
					packageRepositoryURL = d.Absolute.APKRepositoryURL
				}

				distroRepoDir = d.Local.PackagesRepo.Dir
				advisoriesRepoDir = d.Local.AdvisoriesRepo.Dir
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

			var apkindexes []*apk.APKIndex
			for _, arch := range archs {
				idx, err := index.Index(arch, packageRepositoryURL)
				if err != nil {
					return fmt.Errorf("unable to load APKINDEX for %s: %w", arch, err)
				}
				apkindexes = append(apkindexes, idx)
			}

			if err := req.Validate(); err != nil {
				if p.doNotPrompt {
					return fmt.Errorf("not enough information to create advisory: %w", err)
				}

				// prompt for missing fields

				allowedPackages := func() []string {
					return lo.Map(advisoryCfgs.Select().Configurations(), func(cfg v2.Document, _ int) string {
						return cfg.Package.Name
					})
				}

				allowedVulnerabilities := func(packageName string) []string {
					var vulnerabilities []string
					for _, cfg := range advisoryCfgs.Select().WhereName(packageName).Configurations() {
						vulns := lo.FlatMap(cfg.Advisories, func(adv v2.Advisory, _ int) []string {
							return adv.Aliases
						})
						sort.Strings(vulns)
						vulnerabilities = append(vulnerabilities, vulns...)
					}
					return vulnerabilities
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

			opts := advisory.UpdateOptions{
				AdvisoryDocs: advisoryCfgs,
			}

			req.VulnerabilityID, err = advisory.GenerateCGAID(req.Package, req.Aliases[0])
			if err != nil {
				return fmt.Errorf("unable to create advisory id: %w", err)
			}

			err = advisory.Update(cmd.Context(), req, opts)
			if err != nil {
				return err
			}

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type updateParams struct {
	doNotDetectDistro bool
	doNotPrompt       bool

	requestParams                    advisoryRequestParams
	distroRepoDir, advisoriesRepoDir string
	archs                            []string
	packageRepositoryURL             string
}

func (p *updateParams) addFlagsTo(cmd *cobra.Command) {
	addNoDistroDetectionFlag(&p.doNotDetectDistro, cmd)
	addNoPromptFlag(&p.doNotPrompt, cmd)

	p.requestParams.addFlags(cmd)
	addDistroDirFlag(&p.distroRepoDir, cmd)
	addAdvisoriesDirFlag(&p.advisoriesRepoDir, cmd)
	cmd.Flags().StringSliceVar(&p.archs, "arch", []string{"x86_64", "aarch64"}, "package architectures to find published versions for")
	addPackageRepoURLFlag(&p.packageRepositoryURL, cmd)
}
