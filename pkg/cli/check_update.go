package cli

import (
	"log"
	"os"

	"github.com/wolfi-dev/wolfictl/pkg/checks"

	"github.com/spf13/cobra"
)

func CheckUpdate() *cobra.Command {
	o := checks.CheckUpdateOptions{
		Logger: log.New(log.Writer(), "wolfictl check update: ", log.LstdFlags|log.Lmsgprefix),
	}

	cmd := &cobra.Command{
		Use:               "update",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		SilenceErrors:     true,
		Short:             "Check Wolfi update configs",
		RunE: func(cmd *cobra.Command, files []string) error {
			return o.CheckUpdates(cmd.Context(), files)
		},
	}

	checkUpdateFlags(cmd, &o)

	return cmd
}

func checkUpdateFlags(cmd *cobra.Command, o *checks.CheckUpdateOptions) {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	cmd.Flags().StringVarP(&o.Dir, "directory", "d", cwd, "directory containing melange configs")
	cmd.Flags().StringVarP(&o.OverrideVersion, "override-version", "", "", "override the local melange config version to test an update works as expected")
}
