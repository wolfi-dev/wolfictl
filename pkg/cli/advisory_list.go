package cli

import (
	"fmt"
	"sort"

	"chainguard.dev/melange/pkg/build"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
)

func AdvisoryList() *cobra.Command {
	p := &listParams{}
	cmd := &cobra.Command{
		Use:           "list [configs...]",
		Short:         "list advisories for specific packages or across all of Wolfi",
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			index, err := newConfigIndexFromArgs(args...)
			if err != nil {
				return err
			}

			cfgs := index.Configurations()
			var output string

			//nolint:gocritic // rangeValCopy for cfg
			for _, cfg := range cfgs {
				for vuln, entries := range cfg.Advisories {
					if len(entries) == 0 {
						// nothing to show
						continue
					}

					if p.vuln != "" && p.vuln != vuln {
						// user specified a particular different vulnerability
						continue
					}

					latest := advisory.Latest(entries)

					if p.unresolved && latest.Status != vex.StatusAffected && latest.Status != vex.StatusUnderInvestigation {
						// user only wants to see unresolved advisories
						continue
					}

					if p.history {
						sort.SliceStable(entries, func(i, j int) bool {
							return entries[i].Timestamp.Before(entries[j].Timestamp)
						})

						for _, item := range entries {
							timestamp := item.Timestamp
							statusDescription := renderListItem(item)
							output += fmt.Sprintf("%s: %s: %s @ %s\n", cfg.Package.Name, vuln, statusDescription, timestamp)
						}

						continue
					}

					statusDescription := renderListItem(*latest)
					output += fmt.Sprintf("%s: %s: %s\n", cfg.Package.Name, vuln, statusDescription)
				}
			}

			fmt.Print(output)
			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type listParams struct {
	vuln       string
	history    bool
	unresolved bool
}

func (p *listParams) addFlagsTo(cmd *cobra.Command) {
	cmd.Flags().StringVar(&p.vuln, "vuln", "", "vulnerability ID for advisory")
	cmd.Flags().BoolVar(&p.history, "history", false, "show full history for advisories")
	cmd.Flags().BoolVar(&p.unresolved, "unresolved", false, fmt.Sprintf("only show advisories whose latest status is %s or %s", vex.StatusAffected, vex.StatusUnderInvestigation))
}

//nolint:gocritic // hugeParam for entry
func renderListItem(entry build.AdvisoryContent) string {
	switch entry.Status {
	case vex.StatusUnderInvestigation:
		return string(entry.Status)

	case vex.StatusAffected:
		expanded := ""
		if as := entry.ActionStatement; as != "" {
			expanded = fmt.Sprintf(": %s", as)
		}
		return fmt.Sprintf("%s%s", entry.Status, expanded)

	case vex.StatusFixed:
		return fmt.Sprintf("%s (%s)", entry.Status, entry.FixedVersion)

	case vex.StatusNotAffected:
		return fmt.Sprintf("%s (%s)", entry.Status, entry.Justification)
	}

	return "INVALID STATUS"
}
