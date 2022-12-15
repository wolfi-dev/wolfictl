package cli

import (
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/lint"
)

type lintOptions struct {
	args    []string
	verbose bool
}

func Lint() *cobra.Command {
	o := &lintOptions{}
	cmd := &cobra.Command{
		Use:               "lint",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		SilenceErrors:     true,
		Short:             "Lint the code",
		Args:              cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// args[0] can be used to get the path to the file to lint or `.` to lint the current directory
			// what if given yaml is not Melange yaml?
			o.args = args
			return o.LintCmd(o)
		},
	}
	cmd.Flags().BoolVarP(&o.verbose, "verbose", "v", false, "verbose output")
	return cmd
}

func (o lintOptions) LintCmd(options *lintOptions) error {
	linter := lint.New(lint.WithPath(options.args[0]), lint.WithVerbose(options.verbose))
	result, err := linter.Lint()
	if err != nil {
		return err
	}
	linter.Print(result)
	return nil
}
