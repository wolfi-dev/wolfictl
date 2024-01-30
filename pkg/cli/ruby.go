package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
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
		cmdRubyCodeSearch(),
		cmdRubyCheckUpgrade(),
	)
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

func resolvePath(args []string) (path string, isDir bool, err error) {
	if f, err := os.Stat(args[0]); err == nil {
		return args[0], f.IsDir(), nil
	}
	return "", false, fmt.Errorf("%s does not exist", args[0])
}
