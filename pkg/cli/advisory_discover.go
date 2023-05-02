package cli

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/vuln/nvdapi"
)

const defaultSecfixesTrackerHostname = "secfixes-tracker-q67u43ydxq-uc.a.run.app"

//nolint:gosec // This is not a hard-coded credential value, it's the name of the env var to reference.
const envVarNameForNVDAPIKey = "WOLFICTL_NVD_API_KEY"

func AdvisoryDiscover() *cobra.Command {
	p := &discoverParams{}
	cmd := &cobra.Command{
		Use:           "discover",
		Short:         "search for new potential vulnerabilities and create advisories for them",
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			start := time.Now()

			index, err := newConfigIndexFromArgs(args...)
			if err != nil {
				return err
			}

			apiKey := p.resolveNVDAPIKey()

			err = advisory.Discover(advisory.DiscoverOptions{
				BuildCfgs:             index,
				PackageRepositoryURL:  p.packageRepositoryURL,
				Arches:                []string{"x86_64", "aarch64"},
				VulnerabilityDetector: nvdapi.NewDetector(http.DefaultClient, nvdapi.DefaultHost, apiKey),
			})
			if err != nil {
				return err
			}

			finish := time.Now()
			log.Printf("⏱️  vulnerability discovery took %s", finish.Sub(start))

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type discoverParams struct {
	packageRepositoryURL    string
	secfixesTrackerHostname string
	nvdAPIKey               string
}

func (p *discoverParams) addFlagsTo(cmd *cobra.Command) {
	cmd.Flags().StringVar(&p.secfixesTrackerHostname, "host", defaultSecfixesTrackerHostname, "hostname for secfixes-tracker")
	cmd.Flags().StringVar(&p.nvdAPIKey, "nvd-api-key", "", fmt.Sprintf("NVD API key (Can also be set via the environment variable '%s'. Using an API key significantly increases the rate limit for API requests. If you need an NVD API key, go to https://nvd.nist.gov/developers/request-an-api-key .)", envVarNameForNVDAPIKey))
	cmd.Flags().StringVarP(&p.packageRepositoryURL, "package-repo-url", "r", "https://packages.wolfi.dev/os", "URL of the APK package repository")
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
