package cli

import (
	"fmt"

	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/vex/pkg/vex"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
)

func AdvisoryCreate() *cobra.Command {
	p := &createParams{}
	cmd := &cobra.Command{
		Use:           "create <package-name>",
		Short:         "create a new advisory for a package",
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath := args[0]
			index, err := newConfigIndexFromArgs(configPath)
			if err != nil {
				return err
			}

			entry, err := p.advisoryContent()
			if err != nil {
				return err
			}

			err = advisory.Create(advisory.CreateOptions{
				Index:                index,
				Pathname:             configPath,
				Vuln:                 p.vuln,
				InitialAdvisoryEntry: entry,
			})
			if err != nil {
				return err
			}

			if p.sync {
				err := doFollowupSync(index)
				if err != nil {
					return err
				}
			}

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type createParams struct {
	vuln, status, action, impact, justification, timestamp, fixedVersion string
	sync                                                                 bool
}

func (p *createParams) advisoryContent() (*build.AdvisoryContent, error) {
	ts, err := resolveTimestamp(p.timestamp)
	if err != nil {
		return nil, fmt.Errorf("unable to process timestamp: %w", err)
	}

	ac := build.AdvisoryContent{
		Timestamp:       ts,
		Status:          vex.Status(p.status),
		Justification:   vex.Justification(p.justification),
		ImpactStatement: p.impact,
		ActionStatement: p.action,
		FixedVersion:    p.fixedVersion,
	}

	err = ac.Validate()
	if err != nil {
		return nil, fmt.Errorf("unable to create advisory content: %w", err)
	}

	return &ac, nil
}

func (p *createParams) addFlagsTo(cmd *cobra.Command) {
	cmd.Flags().StringVar(&p.vuln, "vuln", "", "vulnerability ID for advisory")
	cmd.MarkFlagRequired("vuln") //nolint:errcheck
	cmd.Flags().StringVar(&p.status, "status", "under_investigation", "status for VEX statement")
	cmd.Flags().StringVar(&p.action, "action", "", "action statement for VEX statement (used only for affected status)")
	cmd.Flags().StringVar(&p.impact, "impact", "", "impact statement for VEX statement (used only for not_affected status)")
	cmd.Flags().StringVar(&p.justification, "justification", "", "justification for VEX statement (used only for not_affected status)")
	cmd.Flags().StringVar(&p.timestamp, "timestamp", "now", "timestamp for VEX statement")
	cmd.Flags().StringVar(&p.fixedVersion, "fixed-version", "", "package version where fix was applied (used only for fixed status)")
	cmd.Flags().BoolVar(&p.sync, "sync", false, "synchronize secfixes data immediately after creating advisory")
}
