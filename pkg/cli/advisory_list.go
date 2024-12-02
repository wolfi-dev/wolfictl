package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/vulnid"
	"github.com/wolfi-dev/wolfictl/pkg/cli/styles"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

//nolint:gocyclo // This CLI command is handling business logic while we experiment with the design; we can factor out common patterns later.
func cmdAdvisoryList() *cobra.Command {
	p := &listParams{}
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List advisories for specific packages, vulnerabilities, or the entire data set",
		Long: `List advisories for specific packages, vulnerabilities, or the entire data set.

The 'list' (or 'ls') command prints a table of advisories based on the given 
selection criteria. By default, all advisories in the current advisory data set 
will be listed.

FILTERING

You can list advisories for a single package:

	wolfictl adv ls -p glibc

You can list all advisories for a given vulnerability ID across all packages:

	wolfictl adv ls -V CVE-2023-38545

You can filter advisories by the type of the latest event:

	wolfictl adv ls -t detection

You can filter advisories by the detected component type:

	wolfictl adv ls -c python

You can filter advisories by the date they were created or last updated:

	wolfictl adv ls --created-since 2024-01-01
	wolfictl adv ls --created-before 2023-12-31
	wolfictl adv ls --updated-since 2024-06-01
	wolfictl adv ls --updated-before 2024-06-01

You can show only advisories that are considered not to be "resolved":

	wolfictl adv ls --unresolved

And you can combine the above flags as needed.

HISTORY

Using the --history flag, you can list advisory events instead of just 
advisories' latest states. This is useful for viewing a summary of an 
investigation over time for a given package/vulnerability match.'

OUTPUT FORMAT

Using the --output (-o) flag, you can select the output format used to render
the results. By default, results are rendered as a "table"; however, you can
also select "json".

COUNT

You get a count of the advisories that match the criteria by using the --count
flag. This will report just the count, not the full list of advisories.

    wolfictl adv ls <various filter flags> --count

`,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if p.history && p.typ != "" {
				return fmt.Errorf("cannot use --history and --type together")
			}

			if p.history && p.count {
				return fmt.Errorf("cannot use --history and --count together")
			}

			p.typ = translateEventTypeAlternativeNames(p.typ)

			if p.typ != "" && !slices.Contains(v2.EventTypes, p.typ) {
				return fmt.Errorf("invalid event type: %s", p.typ)
			}

			if p.outputFormat == "" {
				p.outputFormat = outputFormatTable
			}

			if !slices.Contains(validAdvListOutputFormats, p.outputFormat) {
				return fmt.Errorf(
					"invalid output format %q, must be one of [%s]",
					p.outputFormat,
					strings.Join(validAdvListOutputFormats, ", "),
				)
			}

			if p.advisoriesRepoDir == "" {
				p.advisoriesRepoDir = "." // default to current working directory
			}

			index, err := v2.NewIndex(cmd.Context(), rwos.DirFS(p.advisoriesRepoDir))
			if err != nil {
				return err
			}

			var (
				createdSince, createdBefore, updatedSince, updatedBefore *v2.Timestamp
			)

			const timeLayout = "2006-01-02"

			if p.createdSince != "" {
				t, err := time.Parse(timeLayout, p.createdSince)
				if err != nil {
					return fmt.Errorf("parsing created-since timestamp %q: %w", createdSince, err)
				}
				ts := v2.Timestamp(t)
				createdSince = &ts
			}

			if p.createdBefore != "" {
				t, err := time.Parse(timeLayout, p.createdBefore)
				if err != nil {
					return fmt.Errorf("parsing created-before timestamp %q: %w", createdBefore, err)
				}
				ts := v2.Timestamp(t)
				createdBefore = &ts
			}

			if p.updatedSince != "" {
				t, err := time.Parse(timeLayout, p.updatedSince)
				if err != nil {
					return fmt.Errorf("parsing updated-since timestamp %q: %w", updatedSince, err)
				}
				ts := v2.Timestamp(t)
				updatedSince = &ts
			}

			if p.updatedBefore != "" {
				t, err := time.Parse(timeLayout, p.updatedBefore)
				if err != nil {
					return fmt.Errorf("parsing updated-before timestamp %q: %w", updatedBefore, err)
				}
				ts := v2.Timestamp(t)
				updatedBefore = &ts
			}

			if index.Select().Len() == 0 {
				return fmt.Errorf("no advisory data found in %q; cd to an advisories directory, or use -a flag", p.advisoriesRepoDir)
			}

			var docs []v2.Document
			if pkg := p.packageName; pkg != "" {
				docs = index.Select().WhereName(pkg).Configurations()
			} else {
				docs = index.Select().Configurations()
			}

			var table *advisoryListTableRenderer
			if p.outputFormat == outputFormatTable {
				table = &advisoryListTableRenderer{
					showHistory: p.history,
					showAliases: p.showAliases,
				}
			}

			var resultDocs []v2.Document
			for _, doc := range docs {
				var resultAdvs []v2.Advisory
				for _, adv := range doc.Advisories {
					sortedEvents := adv.SortedEvents()

					if len(sortedEvents) == 0 {
						// nothing to add
						continue
					}

					if p.vuln != "" && !adv.DescribesVulnerability(p.vuln) {
						// user specified a particular different vulnerability
						continue
					}

					if p.unresolved && adv.Resolved() {
						// user wants only unresolved advisories
						continue
					}

					if p.componentType != "" && !advHasDetectedComponentType(adv, p.componentType) {
						// user specified a particular different component type
						continue
					}

					created := sortedEvents[0].Timestamp
					updated := sortedEvents[len(sortedEvents)-1].Timestamp

					if createdSince != nil && !created.After(*createdSince) {
						// user wants only advisories created since a certain date
						continue
					}

					if createdBefore != nil && !created.Before(*createdBefore) {
						// user wants only advisories created before a certain date
						continue
					}

					if updatedSince != nil && !updated.After(*updatedSince) {
						// user wants only advisories updated since a certain date
						continue
					}

					if updatedBefore != nil && !updated.Before(*updatedBefore) {
						// user wants only advisories updated before a certain date
						continue
					}

					if p.history {
						// user wants the full history

						switch p.outputFormat {
						case outputFormatTable:
							for i, event := range sortedEvents {
								isLatest := i == len(sortedEvents)-1 // last event is the latest
								table.add(doc.Package.Name, adv.ID, adv.Aliases, event, isLatest)
							}

						case outputFormatJSON:
							resultAdvs = append(resultAdvs, adv)
						}

						continue
					}

					latest := adv.Latest()

					if p.typ != "" && latest.Type != p.typ {
						// user wants to filter by event type
						continue
					}

					switch p.outputFormat {
					case outputFormatTable:
						table.add(doc.Package.Name, adv.ID, adv.Aliases, latest, true)

					case outputFormatJSON:
						// Since full history wasn't requested, filter the advisory's event list to just
						// the latest.
						prunedAdv := v2.Advisory{
							ID:      adv.ID,
							Aliases: adv.Aliases,
							Events:  []v2.Event{latest},
						}
						resultAdvs = append(resultAdvs, prunedAdv)
					}
				}

				if len(resultAdvs) >= 1 {
					resultDoc := v2.Document{
						SchemaVersion: doc.SchemaVersion,
						Package:       doc.Package,
						Advisories:    resultAdvs,
					}
					resultDocs = append(resultDocs, resultDoc)
				}
			}

			if p.count {
				// Just show the count and then exit.
				fmt.Printf("%d\n", table.len())
				return nil
			}

			switch p.outputFormat {
			case outputFormatTable:
				fmt.Printf("%s\n", table)

			case outputFormatJSON:
				if resultDocs == nil {
					resultDocs = []v2.Document{}
				}

				if err := json.NewEncoder(os.Stdout).Encode(resultDocs); err != nil {
					return fmt.Errorf("encoding JSON: %w", err)
				}
			}

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type listParams struct {
	advisoriesRepoDir string

	packageName   string
	vuln          string
	history       bool
	unresolved    bool
	typ           string
	showAliases   bool
	componentType string
	createdSince  string
	createdBefore string
	updatedSince  string
	updatedBefore string
	count         bool

	outputFormat string
}

var validAdvListOutputFormats = []string{outputFormatTable, outputFormatJSON}

func (p *listParams) addFlagsTo(cmd *cobra.Command) {
	addAdvisoriesDirFlag(&p.advisoriesRepoDir, cmd)

	addPackageFlag(&p.packageName, cmd)
	addVulnFlag(&p.vuln, cmd)

	cmd.Flags().BoolVar(&p.history, "history", false, "show full history for advisories")
	cmd.Flags().BoolVar(&p.unresolved, "unresolved", false, "only show advisories considered to be unresolved")
	cmd.Flags().StringVarP(&p.typ, "type", "t", "", "filter advisories by event type")
	cmd.Flags().BoolVar(&p.showAliases, "aliases", true, "show other known vulnerability IDs for each advisory")
	cmd.Flags().StringVarP(&p.componentType, "component-type", "c", "", "filter advisories by detected component type")
	cmd.Flags().StringVar(&p.createdSince, "created-since", "", "filter advisories created since a given date")
	cmd.Flags().StringVar(&p.createdBefore, "created-before", "", "filter advisories created before a given date")
	cmd.Flags().StringVar(&p.updatedSince, "updated-since", "", "filter advisories updated since a given date")
	cmd.Flags().StringVar(&p.updatedBefore, "updated-before", "", "filter advisories updated before a given date")
	cmd.Flags().BoolVar(&p.count, "count", false, "show only the count of advisories that match the criteria")
	cmd.Flags().StringVarP(&p.outputFormat, "output", "o", "", fmt.Sprintf("output format (%s), defaults to %s", strings.Join(validAdvListOutputFormats, "|"), outputFormatTable))
}

func advHasDetectedComponentType(adv v2.Advisory, componentType string) bool {
	for _, event := range adv.Events {
		if event.Type == v2.EventTypeDetection {
			if data, ok := event.Data.(v2.Detection); ok {
				if data.Type == v2.DetectionTypeScanV1 {
					if data, ok := data.Data.(v2.DetectionScanV1); ok {
						if data.ComponentType == componentType {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

type advisoryListTableRow struct {
	pkg, advID        string
	aliases           []string
	ts, event         string
	isLatestInHistory bool
}

type advisoryListTableRenderer struct {
	// configuration values
	showHistory bool
	showAliases bool

	// internal state
	rows                     []advisoryListTableRow
	currentPkg, currentAdvID string
}

func (r advisoryListTableRenderer) len() int {
	return len(r.rows)
}

func (r *advisoryListTableRenderer) add(pkg, advID string, aliases []string, event v2.Event, isLatest bool) {
	row := advisoryListTableRow{}

	// Don't show the package name again if it's the same as for the prior row
	if pkg != r.currentPkg {
		row.pkg = pkg
		r.currentPkg = pkg
	}

	// Don't show the advisory ID again if it's the same as for the prior event
	if advID != r.currentAdvID {
		row.advID = advID
		if r.showAliases && len(aliases) > 0 {
			row.aliases = aliases
		}

		r.currentAdvID = advID
	}

	if r.showHistory {
		row.ts = event.Timestamp.String()
	}

	row.event = renderListItem(event)
	row.isLatestInHistory = isLatest

	r.rows = append(r.rows, row)
}

func (r advisoryListTableRenderer) String() string {
	var (
		stylePkg            = styles.Bold().Foreground(lipgloss.Color("#3ba0f7"))
		styleAdvID          = lipgloss.NewStyle().Foreground(lipgloss.Color("#bc85ff"))
		styleAliases        = styleAdvID
		styleTS             = lipgloss.NewStyle().Foreground(lipgloss.Color("#7f7f7f"))
		styleNonLatestEvent = lipgloss.NewStyle().Foreground(lipgloss.Color("#a7a7a7"))
	)

	// calculate column widths
	var pkgWidth, advIDWidth, aliasesWidth, tsWidth int
	for _, row := range r.rows {
		if l := len(row.pkg); l > pkgWidth {
			pkgWidth = l
		}
		if l := len(row.advID); l > advIDWidth {
			advIDWidth = l
		}
		if l := calculateAliasesContentWidth(row.aliases); l > aliasesWidth {
			aliasesWidth = l
		}
		if l := len(row.ts); l > tsWidth {
			tsWidth = l
		}
	}

	sb := strings.Builder{}

	// render table
	for _, row := range r.rows {
		sb.WriteString(stylePkg.Render(row.pkg))
		sb.WriteString(strings.Repeat(" ", pkgWidth-len(row.pkg)+1))

		sb.WriteString(styleAdvID.Render(vulnid.Hyperlink(row.advID)))
		sb.WriteString(strings.Repeat(" ", advIDWidth-len(row.advID)+1))

		if r.showAliases {
			if len(row.aliases) == 0 {
				sb.WriteString(strings.Repeat(" ", aliasesWidth+1))
			} else {
				// Normally this would be a simple fmt.Sprintf and strings.Join. However, we
				// need to render each alias as a hyperlink, so we have to do this formatting
				// manually to avoid ANSI escape code clashes.

				asb := strings.Builder{}

				asb.WriteString(styleAliases.Render("("))
				for i, alias := range row.aliases {
					asb.WriteString(styleAliases.Render(vulnid.Hyperlink(alias)))

					if i < len(row.aliases)-1 {
						asb.WriteString(styleAliases.Render(", "))
					}
				}
				asb.WriteString(styleAliases.Render(")"))

				sb.WriteString(asb.String())
				sb.WriteString(strings.Repeat(" ", aliasesWidth-calculateAliasesContentWidth(row.aliases)+1))
			}
		}

		if r.showHistory {
			sb.WriteString(styleTS.Render(row.ts))
			sb.WriteString(strings.Repeat(" ", tsWidth-len(row.ts)+1))
		}

		if row.isLatestInHistory {
			sb.WriteString(row.event)
		} else {
			sb.WriteString(styleNonLatestEvent.Render(row.event))
		}

		sb.WriteString("\n")
	}

	return sb.String()
}

func translateEventTypeAlternativeNames(typ string) string {
	switch typ {
	case "analysis not planned":
		return v2.EventTypeAnalysisNotPlanned

	case "fix not planned":
		return v2.EventTypeFixNotPlanned

	case "pending upstream fix":
		return v2.EventTypePendingUpstreamFix

	case "detected":
		return v2.EventTypeDetection

	case "true positive", "tp", "TP":
		return v2.EventTypeTruePositiveDetermination

	case "fix":
		return v2.EventTypeFixed

	case "false positive", "fp", "FP":
		return v2.EventTypeFalsePositiveDetermination
	}
	return typ
}
func calculateAliasesContentWidth(aliases []string) int {
	if len(aliases) == 0 {
		return 0
	}

	width := 0
	for i, alias := range aliases {
		width += len(alias)

		if i < len(aliases)-1 {
			width += 2 // ", " separator
		}
	}

	width += 2 // parentheses

	return width
}

func renderListItem(event v2.Event) string {
	switch t := event.Type; t {
	case v2.EventTypeAnalysisNotPlanned:
		return "analysis not planned"

	case v2.EventTypeFixNotPlanned:
		return "fix not planned"

	case v2.EventTypePendingUpstreamFix:
		return "pending upstream fix"

	case v2.EventTypeDetection:
		expanded := ""
		if data, ok := event.Data.(v2.Detection); ok && data.Type != "" {
			switch data.Type {
			case v2.DetectionTypeManual:
				return "detected"

			case v2.DetectionTypeNVDAPI:
				if data, ok := data.Data.(v2.DetectionNVDAPI); ok {
					expanded = data.CPEFound
				}

			case v2.DetectionTypeScanV1:
				if data, ok := data.Data.(v2.DetectionScanV1); ok {
					expanded = data.ComponentName
				}
			}
		}
		return fmt.Sprintf("detected (%s)", expanded)

	case v2.EventTypeTruePositiveDetermination:
		expanded := ""
		if data, ok := event.Data.(v2.TruePositiveDetermination); ok && data.Note != "" {
			expanded = data.Note
		}
		return fmt.Sprintf("true positive (%s)", expanded)

	case v2.EventTypeFixed:
		expanded := ""
		if data, ok := event.Data.(v2.Fixed); ok && data.FixedVersion != "" {
			expanded = data.FixedVersion
		}
		return fmt.Sprintf("fixed (%s)", expanded)

	case v2.EventTypeFalsePositiveDetermination:
		expanded := ""
		if data, ok := event.Data.(v2.FalsePositiveDetermination); ok && data.Type != "" {
			expanded = data.Type
		}
		return fmt.Sprintf("false positive (%s)", expanded)
	}

	return "INVALID EVENT TYPE"
}
