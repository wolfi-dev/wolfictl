package cli

import (
	"net/http"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/vuln/sftracker"
)

const defaultSecfixesTrackerHostname = "secfixes-tracker-q67u43ydxq-uc.a.run.app"

func AdvisoryDiscover() *cobra.Command {
	p := &discoverParams{}
	cmd := &cobra.Command{
		Use:           "discover",
		Short:         "search for new potential vulnerabilities and create advisories for them",
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			index, err := newConfigIndexFromArgs(args...)
			if err != nil {
				return err
			}

			secfixesTracker := sftracker.New(
				p.secfixesTrackerHostname,
				http.DefaultClient,
			)

			err = advisory.Discover(advisory.DiscoverOptions{
				Index:                 index,
				VulnerabilitySearcher: secfixesTracker,
			})
			if err != nil {
				return err
			}

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type discoverParams struct {
	secfixesTrackerHostname string
}

func (p *discoverParams) addFlagsTo(cmd *cobra.Command) {
	cmd.Flags().StringVar(&p.secfixesTrackerHostname, "host", defaultSecfixesTrackerHostname, "hostname for secfixes-tracker")
}
