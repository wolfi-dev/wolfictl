package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"

	http2 "github.com/wolfi-dev/wolfictl/pkg/http"
	"github.com/wolfi-dev/wolfictl/pkg/ruby"
)

func cmdRubyCheckUpgrade() *cobra.Command {
	p := &rubyParams{}
	var upgradeVersion string
	cmd := &cobra.Command{
		Use:   "check-upgrade",
		Short: "Check if gemspec for restricts a gem from upgrading to a specified ruby version.",
		Long: `
NOTE: This is currently restricted to ruby code housed on Github as that is the
      majority. There are some on Gitlab and adding Gitlab API support is TODO.
`,
		SilenceErrors: true,
		Hidden:        false,
		Aliases:       []string{"cu"},
		Example: `
# Check if all ruby-3.2 packages in the current directory can be upgraded to ruby-3.3
wolfictl ruby check-upgrade . --ruby-version 3.2 --ruby-upgrade-version 3.3
`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			path, isDir, err := resolvePath(args)
			if err != nil {
				return fmt.Errorf("could not resolve path: %w", err)
			}

			if p.version == "" && isDir {
				return fmt.Errorf("directory specified, but no --ruby-version to search for")
			}

			if upgradeVersion == "" {
				return fmt.Errorf("no ruby upgrade version specified (--ruby-upgrade-version, -u)")
			}

			client := &http2.RLHTTPClient{
				Client: oauth2.NewClient(ctx, ghTokenSource{}),

				// 1 request every (n) second(s) to avoid DOS'ing server.
				// https://docs.github.com/en/rest/guides/best-practices-for-integrators?apiVersion=2022-11-28#dealing-with-secondary-rate-limits
				Ratelimiter: rate.NewLimiter(rate.Every(5*time.Second), 1),
			}

			opts := ruby.Options{
				RubyVersion:       p.version,
				RubyUpdateVersion: upgradeVersion,
				Path:              path,
				Client:            client,
				NoCache:           p.noCache,
			}

			pkgs, err := opts.DiscoverRubyPackages(ctx)
			if err != nil {
				return fmt.Errorf("could not discover ruby packages: %w", err)
			}

			checkUpdateError := false
			for i := range pkgs {
				// Check gemspec for version constraints
				err = opts.CheckUpgrade(ctx, &pkgs[i])
				if err != nil {
					fmt.Printf("❌ %s: %s\n", pkgs[i].Name, err.Error())
					checkUpdateError = true
				} else {
					fmt.Printf("✅ %s\n", pkgs[i].Name)
				}
			}

			if checkUpdateError {
				return fmt.Errorf("errors checking ruby upgrade")
			}
			return nil
		},
	}

	p.addFlagsTo(cmd)
	cmd.Flags().StringVarP(&upgradeVersion, "ruby-upgrade-version", "u", "", "ruby version to check for updates")
	return cmd
}
