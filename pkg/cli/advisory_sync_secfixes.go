package cli

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func AdvisorySyncSecfixes() *cobra.Command {
	p := &syncSecfixesParams{}
	cmd := &cobra.Command{
		Deprecated:    "'secfixes' data is no longer used. This command does nothing, and will be removed in a future version.",
		Use:           "sync-secfixes",
		Short:         "synchronize secfixes and advisories for specific packages or across all of Wolfi",
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			log.Print("Did nothing!")

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type syncSecfixesParams struct {
	doNotDetectDistro bool

	advisoriesRepoDir string

	packageName string

	warn bool
}

func (p *syncSecfixesParams) addFlagsTo(cmd *cobra.Command) {
	addNoDistroDetectionFlag(&p.doNotDetectDistro, cmd)

	addAdvisoriesDirFlag(&p.advisoriesRepoDir, cmd)

	addPackageFlag(&p.packageName, cmd)

	cmd.Flags().BoolVar(&p.warn, "warn", false, "don't write changes to files, but exit 1 if there would be changes")
}
