package cli

import (
	"context"
	"fmt"
	"net/http"

	vulnadvs "github.com/chainguard-dev/advisory-schema/pkg/vuln"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/vulnid"
)

func cmdAdvisoryAliasFind() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "find <vulnerability ID> [<vulnerability ID>...]",
		Short: "Query upstream data sources for aliases for the given vulnerability ID(s)",
		Long: `This is a utility command to query upstream data sources to find aliases for 
the given vulnerability ID(s).

Vulnerability IDs can be CVE IDs (e.g. CVE-2021-44228) or GHSA IDs (e.g. 
GHSA-jfh8-c2jp-5v3q).

You may specify multiple vulnerability IDs at once.

If your terminal supports hyperlinks, vulnerability IDs in the output will be 
hyperlinked to the relevant webpage from the upstream data source.
`,
		Example: `
	$ wolfictl adv alias find CVE-2021-44228
	Aliases for CVE-2021-44228:
	  - GHSA-jfh8-c2jp-5v3q



	$ wolfictl adv alias find GHSA-f9jg-8p32-2f55 CVE-2020-8552
	Aliases for GHSA-f9jg-8p32-2f55:
	  - CVE-2021-25743

	Aliases for CVE-2020-8552:
	  - GHSA-82hx-w2r5-c2wq`,
		SilenceErrors: true,
		Args:          cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			af := advisory.NewHTTPAliasFinder(http.DefaultClient)

			for i, arg := range args {
				aliases, err := findAliases(cmd.Context(), af, arg)
				if err != nil {
					return fmt.Errorf("finding aliases for %q: %w", arg, err)
				}

				fmt.Printf("Aliases for %s:\n", vulnid.Hyperlink(arg))

				for _, alias := range aliases {
					fmt.Printf("  - %s\n", vulnid.Hyperlink(alias))
				}

				// Add a blank line between queries.
				if i < len(args)-1 {
					fmt.Println()
				}
			}

			return nil
		},
	}

	return cmd
}

func findAliases(ctx context.Context, af advisory.AliasFinder, vulnerabilityID string) ([]string, error) {
	switch {
	case vulnadvs.RegexCVE.MatchString(vulnerabilityID):
		return af.GHSAsForCVE(ctx, vulnerabilityID)

	case vulnadvs.RegexGHSA.MatchString(vulnerabilityID):
		cve, err := af.CVEForGHSA(ctx, vulnerabilityID)
		if err != nil {
			return nil, err
		}
		if cve == "" {
			return nil, nil
		}

		return []string{cve}, nil

	default:
		return nil, fmt.Errorf("unknown vulnerability ID format: %q", vulnerabilityID)
	}
}
