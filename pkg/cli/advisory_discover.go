package cli

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"chainguard.dev/melange/pkg/config"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/advisory/matchwatcher"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	buildconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/build"
	rwfsOS "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
	"github.com/wolfi-dev/wolfictl/pkg/vuln/nvdapi"
	"golang.org/x/sync/errgroup"
)

//nolint:gosec // This is not a hard-coded credential value, it's the name of the env var to reference.
const envVarNameForNVDAPIKey = "WOLFICTL_NVD_API_KEY"

func cmdAdvisoryDiscover() *cobra.Command {
	p := &discoverParams{}
	cmd := &cobra.Command{
		Use:           "discover",
		Short:         "Automatically create advisories by matching distro packages to vulnerabilities in NVD",
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
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

				distroRepoDir = d.Local.PackagesRepo.Dir
				advisoriesRepoDir = d.Local.AdvisoriesRepo.Dir

				if packageRepositoryURL == "" {
					packageRepositoryURL = d.Absolute.APKRepositoryURL
				}

				_, _ = fmt.Fprint(os.Stderr, renderDetectedDistro(d))
			}

			advisoriesFsys := rwfsOS.DirFS(advisoriesRepoDir)
			advisoryCfgs, err := v2.NewIndex(advisoriesFsys)
			if err != nil {
				return err
			}

			fsys := rwfsOS.DirFS(distroRepoDir)
			buildCfgs, err := buildconfigs.NewIndex(fsys)
			if err != nil {
				return fmt.Errorf("unable to select packages: %w", err)
			}

			selectedPackages := getSelectedOrDistroPackages(p.packageName, buildCfgs)
			apiKey := p.resolveNVDAPIKey()

			ctx := context.Background()
			g, ctx := errgroup.WithContext(ctx)
			events := make(chan interface{})

			g.Go(func() error {
				defer close(events)
				model := matchwatcher.New(events, len(selectedPackages))
				final, err := tea.NewProgram(model, tea.WithContext(ctx)).Run()

				if err != nil {
					return err
				}

				if m, ok := final.(matchwatcher.Model); ok && m.Err != nil {
					return m.Err
				}

				// Return a sentinel error to cancel the other goroutines.
				return errNormalExit
			})

			g.Go(func() error {
				err = advisory.Discover(ctx, advisory.DiscoverOptions{
					SelectedPackages:      selectedPackages,
					BuildCfgs:             buildCfgs,
					AdvisoryDocs:          advisoryCfgs,
					PackageRepositoryURL:  packageRepositoryURL,
					Arches:                []string{"x86_64", "aarch64"},
					VulnerabilityDetector: nvdapi.NewDetector(http.DefaultClient, nvdapi.DefaultHost, apiKey),
					VulnEvents:            events,
				})
				return err
			})

			if err := g.Wait(); err != nil {
				if errors.Is(err, errNormalExit) {
					return nil
				}

				return err
			}

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

var errNormalExit = errors.New("normal exit")

type discoverParams struct {
	doNotDetectDistro bool

	packageName string

	distroRepoDir, advisoriesRepoDir string

	packageRepositoryURL string

	nvdAPIKey string
}

func (p *discoverParams) addFlagsTo(cmd *cobra.Command) {
	addNoDistroDetectionFlag(&p.doNotDetectDistro, cmd)

	addPackageFlag(&p.packageName, cmd)

	addDistroDirFlag(&p.distroRepoDir, cmd)
	addAdvisoriesDirFlag(&p.advisoriesRepoDir, cmd)

	cmd.Flags().StringVarP(&p.packageRepositoryURL, "package-repo-url", "r", "", "URL of the APK package repository")

	cmd.Flags().StringVar(&p.nvdAPIKey, "nvd-api-key", "", fmt.Sprintf("NVD API key (Can also be set via the environment variable '%s'. Using an API key significantly increases the rate limit for API requests. If you need an NVD API key, go to https://nvd.nist.gov/developers/request-an-api-key.)", envVarNameForNVDAPIKey))
}

func (p *discoverParams) resolveNVDAPIKey() string {
	// TODO: use Viper for this!

	if p.nvdAPIKey != "" {
		return p.nvdAPIKey
	}

	keyFromEnv := os.Getenv(envVarNameForNVDAPIKey)
	if keyFromEnv != "" {
		return keyFromEnv
	}

	log.Print("⚠️  no NVD API key supplied. Searching NVD will be significantly faster if you use an API key. See command help for more information.")

	return ""
}

func getSelectedOrDistroPackages(packageName string, buildCfgs *configs.Index[config.Configuration]) []string {
	if packageName != "" {
		return []string{packageName}
	}

	var pkgs []string
	buildCfgs.Select().Each(func(e configs.Entry[config.Configuration]) {
		pkgs = append(pkgs, e.Configuration().Package.Name)
	})

	return pkgs
}
