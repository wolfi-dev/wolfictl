package cli

import (
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/lint"
)

type lintOptions struct {
	args    []string
	verbose bool
	list    bool
}

func Lint() *cobra.Command {
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
			return o.LintCmd()
		},
	}
	cmd.Flags().BoolVarP(&o.verbose, "verbose", "v", false, "verbose output")
	cmd.Flags().BoolVarP(&o.list, "list", "l", false, "enable printing all of the lint rules")
	return cmd
}

func (o lintOptions) LintCmd() error {
	linter := lint.New(o.makeLintOptions())
	result, err := linter.Lint()
	if err != nil {
		return err
	}
	if !o.list {
		linter.Print(result)
	}
	return nil
}

func (o lintOptions) makeLintOptions() []lint.Option {
	var lo []lint.Option

	if len(o.args) == 0 {
		// Lint the current directory by default.
		o.args = []string{"."}
	}

	lo = append(lo, lint.WithPath(o.args[0]))

	if o.verbose {
		lo = append(lo, lint.WithVerbose(o.verbose))
	}

	if o.list {
		lo = append(lo, lint.WithList(o.list))
	}
	return lo
}
