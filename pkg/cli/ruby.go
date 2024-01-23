package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"

	http2 "github.com/wolfi-dev/wolfictl/pkg/http"
	"github.com/wolfi-dev/wolfictl/pkg/ruby"
)

func cmdRuby() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ruby",
		Short: "Work with ruby packages",
		Long: `Work with ruby packages

The ruby subcommand is intended to work with all ruby packages inside the wolfi
repo. The main uses right now are to check if the ruby version can be upgraded,
and run Github code searches for Github repos pulled from melange yaml files.

This command takes a path to the wolfi-dev/os repository as an argument. The
path can either be the directory itself to discover all files using ruby-* or
a specific melange yaml to work with.

NOTE: This is currently restricted to ruby code housed on Github as that is the
      majority. There are some on Gitlab and adding Gitlab API support is TODO.
`,
		SilenceErrors: true,
		Hidden:        false,
		Example: `
# Run a search query over all ruby-3.2 package in the current directory
wolfictl ruby code-search . --ruby-version 3.2 --search-term 'language:ruby racc'

# Check if all ruby-3.2 packages in the current directory can be upgraded to ruby-3.3
wolfictl ruby check-upgrade . --ruby-version 3.2 --ruby-upgrade-version 3.3
`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				cmd.Help() //nolint:errcheck
				return
			}
		},
	}

	cmd.AddCommand(
		cmdCodeSearch(),
		cmdCheckUpgrade(),
	)
	return cmd
}

func cmdCodeSearch() *cobra.Command {
	p := &rubyParams{}
	var searchTerm string
	cmd := &cobra.Command{
		Use:   "code-search",
		Short: "Run Github search queries for ruby packages.",
		Long: `
NOTE: Due to limitations of GitHub Code Search, the search terms are only matched
      against the default branch rather than the tag from which the package is
      built. Hopefully this gets better in the future but it could lead to false
      negatives if upgrade work has been committed to the main branch but a release
      has not been cut yet.

      https://docs.github.com/en/rest/search/search?apiVersion=2022-11-28#search-code

NOTE: This is currently restricted to ruby code housed on Github as that is the
      majority. There are some on Gitlab and adding Gitlab API support is TODO.
`,
		SilenceErrors: true,
		Hidden:        false,
		Aliases:       []string{"cs", "search"},
		Example: `
# Run a search query over all ruby-3.2 package in the current directory
wolfictl ruby code-search . --ruby-version 3.2 --search-term 'language:ruby racc'
`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if p.version == "" {
				return fmt.Errorf("No ruby version specified")
			}

			path, err := resolvePath(args)
			if err != nil {
				return fmt.Errorf("Could not resolve path: %w", err)
			}

			client := &http2.RLHTTPClient{
				Client: oauth2.NewClient(context.Background(), ghTokenSource{}),

				// 1 request every (n) second(s) to avoid DOS'ing server.
				// https://docs.github.com/en/rest/guides/best-practices-for-integrators?apiVersion=2022-11-28#dealing-with-secondary-rate-limits
				Ratelimiter: rate.NewLimiter(rate.Every(5*time.Second), 1),
			}

			opts := ruby.RubyOptions{
				RubyVersion: p.version,
				SearchTerm:  searchTerm,
				Path:        path,
				Client:      client,
				NoCache:     p.noCache,
			}

			pkgs, err := opts.DiscoverRubyPackages()
			if err != nil {
				return fmt.Errorf("Could not discover ruby packages: %w", err)
			}

			codeSearchError := false
			for _, pkg := range pkgs {
				// Check gemspec for version constraints
				err = opts.CodeSearch(&pkg, searchTerm)
				if err != nil {
					fmt.Printf("⚠️ %s: %s\n", pkg.Name, err.Error())
					codeSearchError = true
				} else {
					fmt.Printf("✅ %s\n", pkg.Name)
				}
			}

			if codeSearchError {
				return fmt.Errorf("Errors checking ruby upgrade")
			}
			return nil
		},
	}

	p.addFlagsTo(cmd)
	cmd.Flags().StringVarP(&searchTerm, "search-term", "s", "", "GitHub code search term")
	return cmd
}

func cmdCheckUpgrade() *cobra.Command {
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
			if p.version == "" {
				return fmt.Errorf("No ruby version specified (--ruby-version, -r)")
			}

			if upgradeVersion == "" {
				return fmt.Errorf("No ruby upgrade version specified (--ruby-upgrade-version, -u)")
			}

			path, err := resolvePath(args)
			if err != nil {
				return fmt.Errorf("Could not resolve path: %w", err)
			}

			client := &http2.RLHTTPClient{
				Client: oauth2.NewClient(context.Background(), ghTokenSource{}),

				// 1 request every (n) second(s) to avoid DOS'ing server.
				// https://docs.github.com/en/rest/guides/best-practices-for-integrators?apiVersion=2022-11-28#dealing-with-secondary-rate-limits
				Ratelimiter: rate.NewLimiter(rate.Every(5*time.Second), 1),
			}

			opts := ruby.RubyOptions{
				RubyVersion:       p.version,
				RubyUpdateVersion: upgradeVersion,
				Path:              path,
				Client:            client,
				NoCache:           p.noCache,
			}

			pkgs, err := opts.DiscoverRubyPackages()
			if err != nil {
				return fmt.Errorf("Could not discover ruby packages: %w", err)
			}

			checkUpdateError := false
			for _, pkg := range pkgs {
				// Check gemspec for version constraints
				err = opts.CheckUpgrade(&pkg)
				if err != nil {
					fmt.Printf("❌ %s: %s\n", pkg.Name, err.Error())
					checkUpdateError = true
				} else {
					fmt.Printf("✅ %s\n", pkg.Name)
				}
			}

			if checkUpdateError {
				return fmt.Errorf("Errors checking ruby upgrade")
			}
			return nil
		},
	}

	p.addFlagsTo(cmd)
	cmd.Flags().StringVarP(&upgradeVersion, "ruby-upgrade-version", "u", "", "ruby version to check for updates")
	return cmd
}

type rubyParams struct {
	version string
	noCache bool
}

func (p *rubyParams) addFlagsTo(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&p.version, "ruby-version", "r", "", "ruby version to search for")
	cmd.Flags().BoolVar(&p.noCache, "no-cache", false, "do not use cached results")
}

func resolvePath(args []string) (string, error) {
	if _, err := os.Stat(args[0]); err == nil {
		return args[0], nil
	}
	return "", fmt.Errorf("%s does not exist", args[0])
}
