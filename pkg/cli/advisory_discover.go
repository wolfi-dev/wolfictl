package cli

import (
	"net/http"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/vuln/sftracker"
)

func AdvisoryDiscover() *cobra.Command {
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
				"secfixes-tracker-nd2dq3gc7a-uk.a.run.app",
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

	return cmd
}
