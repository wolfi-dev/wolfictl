package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
)

func cmdAdvisoryList() *cobra.Command {
	p := &listParams{}
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List advisories for specific packages, vulnerabilities, or the entire data set",
		Long: `List advisories for specific packages, vulnerabilities, or the entire data set.

The 'list' (or 'ls') command prints a list of advisories based on the given 
selection criteria. By default, all advisories in the current advisory data set 
will be listed.

FILTERING

You can list advisories for a single package:

	wolfictl adv ls -p glibc

You can list all advisories for a given vulnerability ID across all packages:

	wolfictl adv ls -V CVE-2023-38545

You can show only advisories that are considered not to be "resolved":

	wolfictl adv ls --unresolved

And you can combine the above flags as needed.

HISTORY

Using the --history flag, you can list advisory events instead of just 
advisories' latest states. This is useful for viewing a summary of an 
investigation over time for a given package/vulnerability match.'
`,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			advisoriesRepoDir := resolveAdvisoriesDirInput(p.advisoriesRepoDir)
			if advisoriesRepoDir == "" {
				if p.doNotDetectDistro {
					return fmt.Errorf("no advisories repo dir specified")
				}

				d, err := distro.Detect()
				if err != nil {
					return fmt.Errorf("no advisories repo dir specified, and distro auto-detection failed: %w", err)
				}

				advisoriesRepoDir = d.Local.AdvisoriesRepo.Dir
				_, _ = fmt.Fprint(os.Stderr, renderDetectedDistro(d))
			}

			advisoriesFsys := rwos.DirFS(advisoriesRepoDir)
			advisoryCfgs, err := v2.NewIndex(cmd.Context(), advisoriesFsys)
			if err != nil {
				return err
			}

			var cfgs []v2.Document
			if pkg := p.packageName; pkg != "" {
				cfgs = advisoryCfgs.Select().WhereName(pkg).Configurations()
			} else {
				cfgs = advisoryCfgs.Select().Configurations()
			}

			var output string

			for _, cfg := range cfgs {
				for _, adv := range cfg.Advisories {
					if len(adv.Events) == 0 {
						// nothing to show
						continue
					}

					if p.vuln != "" && !adv.DescribesVulnerability(p.vuln) {
						// user specified a particular different vulnerability
						continue
					}

					if p.unresolved && adv.Resolved() {
						// user only wants to see unresolved advisories
						continue
					}

					vulnID := adv.ID
					if len(adv.Aliases) > 0 {
						vulnID += fmt.Sprintf(" (%s)", strings.Join(adv.Aliases, ", "))
					}

					if p.history {
						// user wants to see the full history
						sorted := adv.SortedEvents()
						for _, event := range sorted {
							statusDescription := renderListItem(event)
							timestamp := event.Timestamp

							output += fmt.Sprintf(
								"%s: %s: %s @ %s\n",
								cfg.Package.Name,
								vulnID,
								statusDescription,
								timestamp,
							)
						}

						continue
					}

					statusDescription := renderListItem(adv.Latest())
					output += fmt.Sprintf("%s: %s: %s\n", cfg.Package.Name, vulnID, statusDescription)
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
	cmd.Flags().BoolVar(&p.unresolved, "unresolved", false, "only show advisories considered to be unresolved")
}

func renderListItem(event v2.Event) string {
	switch t := event.Type; t {
	case v2.EventTypeAnalysisNotPlanned,
		v2.EventTypeFixNotPlanned,
		v2.EventTypePendingUpstreamFix:
		return t

	case v2.EventTypeDetection:
		expanded := ""
		if data, ok := event.Data.(v2.Detection); ok && data.Type != "" {
			switch data.Type {
			case v2.DetectionTypeManual:
				expanded = "manual"

			case v2.DetectionTypeNVDAPI:
				if data, ok := data.Data.(v2.DetectionNVDAPI); ok {
					expanded = fmt.Sprintf("nvdapi: %s", data.CPEFound)
				}
			}
		}
		return fmt.Sprintf("%s (%s)", t, expanded)

	case v2.EventTypeTruePositiveDetermination:
		expanded := ""
		if data, ok := event.Data.(v2.TruePositiveDetermination); ok && data.Note != "" {
			expanded = data.Note
		}
		return fmt.Sprintf("%s (%s)", t, expanded)

	case v2.EventTypeFixed:
		expanded := ""
		if data, ok := event.Data.(v2.Fixed); ok && data.FixedVersion != "" {
			expanded = data.FixedVersion
		}
		return fmt.Sprintf("%s (%s)", t, expanded)

	case v2.EventTypeFalsePositiveDetermination:
		expanded := ""
		if data, ok := event.Data.(v2.FalsePositiveDetermination); ok && data.Type != "" {
			expanded = data.Type
		}
		return fmt.Sprintf("%s (%s)", t, expanded)
	}

	return "INVALID EVENT TYPE"
}
