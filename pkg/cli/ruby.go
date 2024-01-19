package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/ruby"
)

func cmdRuby() *cobra.Command {
	p := &rubyParams{}
	cmd := &cobra.Command{
		Use:           "ruby",
		Short:         "Work with ruby packages",
		SilenceErrors: true,
		Hidden:        false,
		Args:          cobra.MinimumNArgs(1),
		Example: `
# Query all ruby packages within the current directory
wolfictl ruby --ruby-version 3.2 .
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if p.version == "" {
				return fmt.Errorf("No ruby version specified")
			}

			if p.updateVersion == "" {
				return fmt.Errorf("No ruby update version specified")
			}

			path, err := resolvePath(args)
			if err != nil {
				return fmt.Errorf("Could not resolve path: %w", err)
			}

			opts := ruby.RubyOptions{
				All:               p.all,
				RubyVersion:       p.version,
				RubyUpdateVersion: p.updateVersion,
				Path:              path,
			}

			results, err := ruby.Operate(opts)
			if err != nil {
				return fmt.Errorf("unable to list packages: %w", err)
			}

			fmt.Println(strings.Join(results, "\n"))

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type rubyParams struct {
	all           bool
	version       string
	updateVersion string
}

func (p *rubyParams) addFlagsTo(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&p.all, "all", true, "capture all packages")
	cmd.Flags().StringVarP(&p.version, "ruby-version", "r", "", "ruby version to search for")
	cmd.Flags().StringVarP(&p.updateVersion, "ruby-update-version", "u", "", "ruby version to check for updates")
}

func resolvePath(args []string) (string, error) {
	if _, err := os.Stat(args[0]); err == nil {
		return args[0], nil
	}
	return "", fmt.Errorf("%s does not exist", args[0])
}
