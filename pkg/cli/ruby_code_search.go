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

func cmdRubyCodeSearch() *cobra.Command {
	p := &rubyParams{}
	var searchTerms []string
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
wolfictl ruby code-search . --ruby-version 3.2 --search-terms 'language:ruby racc'
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

			client := &http2.RLHTTPClient{
				Client: oauth2.NewClient(ctx, ghTokenSource{}),

				// 1 request every (n) second(s) to avoid DOS'ing server.
				// https://docs.github.com/en/rest/guides/best-practices-for-integrators?apiVersion=2022-11-28#dealing-with-secondary-rate-limits
				Ratelimiter: rate.NewLimiter(rate.Every(5*time.Second), 1),
			}

			opts := ruby.Options{
				RubyVersion: p.version,
				Path:        path,
				Client:      client,
				NoCache:     p.noCache,
			}

			pkgs, err := opts.DiscoverRubyPackages(ctx)
			if err != nil {
				return fmt.Errorf("could not discover ruby packages: %w", err)
			}

			codeSearchError := false
			for i := range pkgs {
				// Check gemspec for version constraints
				var localErr string
				for _, term := range searchTerms {
					err = opts.CodeSearch(ctx, &pkgs[i], term)
					if err != nil {
						localErr += fmt.Sprintf(" |query='%s': %v", term, err)
					}
				}
				if localErr != "" {
					fmt.Printf("⚠️ %s: %s\n", pkgs[i].Name, localErr)
					codeSearchError = true
				} else {
					fmt.Printf("✅ %s\n", pkgs[i].Name)
				}
			}

			if codeSearchError {
				return fmt.Errorf("errors checking ruby upgrade")
			}
			return nil
		},
	}

	p.addFlagsTo(cmd)
	cmd.Flags().StringArrayVarP(&searchTerms, "search-terms", "s", []string{}, "GitHub code search term")
	return cmd
}
