package cli

import (
	"fmt"
	"os"
	"sort"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	advisoryconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v1"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
)

func AdvisoryList() *cobra.Command {
	p := &listParams{}
	cmd := &cobra.Command{
		Use:           "list",
		Short:         "list advisories for specific packages or across all of Wolfi",
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			advisoriesRepoDir := resolveAdvisoriesDir(p.advisoriesRepoDir)
			if advisoriesRepoDir == "" {
				if p.doNotDetectDistro {
					return fmt.Errorf("no advisories repo dir specified")
				}

				d, err := distro.Detect()
				if err != nil {
					return fmt.Errorf("no advisories repo dir specified, and distro auto-detection failed: %w", err)
				}

				advisoriesRepoDir = d.AdvisoriesRepoDir
				_, _ = fmt.Fprint(os.Stderr, renderDetectedDistro(d))
			}

			advisoriesFsys := rwos.DirFS(advisoriesRepoDir)
			advisoryCfgs, err := advisoryconfigs.NewIndex(advisoriesFsys)
			if err != nil {
				return err
			}

			var cfgs []advisoryconfigs.Document
			if pkg := p.packageName; pkg != "" {
				cfgs = advisoryCfgs.Select().WhereName(pkg).Configurations()
			} else {
				cfgs = advisoryCfgs.Select().Configurations()
			}

			var output string

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
	doNotDetectDistro bool

	advisoriesRepoDir string

	packageName string
	vuln        string
	history     bool
	unresolved  bool
}

func (p *listParams) addFlagsTo(cmd *cobra.Command) {
	addNoDistroDetectionFlag(&p.doNotDetectDistro, cmd)

	addAdvisoriesDirFlag(&p.advisoriesRepoDir, cmd)

	addPackageFlag(&p.packageName, cmd)
	addVulnFlag(&p.vuln, cmd)

	cmd.Flags().BoolVar(&p.history, "history", false, "show full history for advisories")
	cmd.Flags().BoolVar(&p.unresolved, "unresolved", false, fmt.Sprintf("only show advisories whose latest status is %s or %s", vex.StatusAffected, vex.StatusUnderInvestigation))
}

func renderListItem(entry advisoryconfigs.Entry) string {
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
