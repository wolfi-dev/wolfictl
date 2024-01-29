package cli

import (
	"context"
	"errors"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/lint"
)

type lintOptions struct {
	args      []string
	list      bool
	skipRules []string
}

func cmdLint() *cobra.Command {
	o := &lintOptions{}
	cmd := &cobra.Command{
		Use:               "lint",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		SilenceErrors:     true,
		Short:             "Lint the code",
		RunE: func(cmd *cobra.Command, args []string) error {
			// args[0] can be used to get the path to the file to lint or `.` to lint the current directory
			// what if given yaml is not Melange yaml?
			o.args = args
			return o.LintCmd(cmd.Context())
		},
	}
	cmd.Flags().BoolVarP(&o.list, "list", "l", false, "prints the all of available rules and exits")
	cmd.Flags().StringArrayVarP(&o.skipRules, "skip-rule", "", []string{}, "list of rules to skip")

	cmd.AddCommand(cmdLintYam())

	return cmd
}

func (o lintOptions) LintCmd(ctx context.Context) error {
	linter := lint.New(o.makeLintOptions()...)

	// If the list flag is set, print the list of available rules and exit.
	if o.list {
		linter.PrintRules(ctx)
		return nil
	}

	// Run the linter.
	result, err := linter.Lint(ctx)
	if err != nil {
		return err
	}
	if result.HasErrors() {
		linter.Print(ctx, result)
		return errors.New("linting failed")
	}
	return nil
}

func (o lintOptions) makeLintOptions() []lint.Option {
	if len(o.args) == 0 {
		// Lint the current directory by default.
		o.args = []string{"."}
	}

	return []lint.Option{
		lint.WithPath(o.args[0]),
		lint.WithSkipRules(o.skipRules),
	}
}
