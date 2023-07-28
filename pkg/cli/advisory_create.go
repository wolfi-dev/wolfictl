package cli

import (
	"fmt"
	"os"

	"chainguard.dev/melange/pkg/config"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/advisory/prompt"
	advisoryconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/advisory"
	buildconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/build"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
	"github.com/wolfi-dev/wolfictl/pkg/index"
	"gitlab.alpinelinux.org/alpine/go/repository"
)

func AdvisoryCreate() *cobra.Command {
	p := &createParams{}
	cmd := &cobra.Command{
		Use:           "create",
		Short:         "create a new advisory for a package",
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			archs := p.archs
			packageRepositoryURL := p.packageRepositoryURL
			distroRepoDir := resolveDistroDir(p.distroRepoDir)
			advisoriesRepoDir := resolveAdvisoriesDir(p.advisoriesRepoDir)
			if distroRepoDir == "" || advisoriesRepoDir == "" {
				if p.doNotDetectDistro {
					return fmt.Errorf("distro repo dir and/or advisories repo dir was left unspecified")
				}

				d, err := distro.Detect()
				if err != nil {
					return fmt.Errorf("distro repo dir and/or advisories repo dir was left unspecified, and distro auto-detection failed: %w", err)
				}

				if len(archs) == 0 {
					archs = d.SupportedArchitectures
				}

				if packageRepositoryURL == "" {
					packageRepositoryURL = d.APKRepositoryURL
				}

				distroRepoDir = d.DistroRepoDir
				advisoriesRepoDir = d.AdvisoriesRepoDir
				_, _ = fmt.Fprint(os.Stderr, renderDetectedDistro(d))
			}

			advisoryFsys := rwos.DirFS(advisoriesRepoDir)
			advisoryCfgs, err := advisoryconfigs.NewIndex(advisoryFsys)
			if err != nil {
				return err
			}

			fsys := rwos.DirFS(distroRepoDir)
			buildCfgs, err := buildconfigs.NewIndex(fsys)
			if err != nil {
				return fmt.Errorf("unable to select packages: %w", err)
			}

			req, err := p.requestParams.advisoryRequest()
			if err != nil {
				return err
			}

			var apkindexes []*repository.ApkIndex
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
					return lo.Map(buildCfgs.Select().Configurations(), func(cfg config.Configuration, _ int) string {
						return cfg.Package.Name
					})
				}

				allowedVulnerabilities := func(packageName string) []string {
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
				AdvisoryCfgs: advisoryCfgs,
			}

			err = advisory.Create(req, opts)
			if err != nil {
				return err
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
	cmd.Flags().StringVarP(&p.packageRepositoryURL, "package-repo-url", "r", "", "URL of the APK package repository")
}
