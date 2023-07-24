package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/samber/lo"
	"github.com/savioxavier/termlink"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/scan"
)

const (
	outputFormatOutline = "outline"
	outputFormatJSON    = "json"
)

func Scan() *cobra.Command {
	p := &scanParams{}
	cmd := &cobra.Command{
		Use:           "scan <path/to/package.apk> ...",
		Short:         "Scan an apk file for vulnerabilities",
		Args:          cobra.MinimumNArgs(1),
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if p.outputFormat == "" {
				p.outputFormat = outputFormatOutline
			}

			if p.outputFormat != outputFormatJSON && p.outputFormat != outputFormatOutline {
				return fmt.Errorf("invalid output format %q, must be one of [%s]", p.outputFormat, strings.Join([]string{outputFormatOutline, outputFormatJSON}, ", "))
			}

			var results []Result

			for _, arg := range args {
				inputFilePath := arg
				inputFile, err := os.Open(inputFilePath)
				if err != nil {
					return fmt.Errorf("failed to open input file: %w", err)
				}

				fmt.Fprintf(os.Stderr, "Will process: %s\n", path.Base(inputFilePath))

				var findings []*scan.Finding
				if p.sbomInput {
					findings, err = scan.APKSBOM(inputFile, p.localDBFilePath)
				} else {
					findings, err = scan.APK(inputFile, p.localDBFilePath)
				}
				if err != nil {
					return fmt.Errorf("failed to scan: %w", err)
				}
				inputFile.Close()

				results = append(results, Result{
					Target: Target{
						File:     path.Base(inputFilePath),
						FullPath: inputFilePath,
					},
					Findings: findings,
				})

				if p.outputFormat == outputFormatOutline {
					if len(findings) == 0 {
						fmt.Println("✅ No vulnerabilities found")
					} else {
						tree := newFindingsTree(findings)
						fmt.Println(tree.render())
					}
				}

				if p.requireZeroFindings && len(findings) > 0 {
					return fmt.Errorf("more than 0 vulnerabilities found")
				}
			}

			if p.outputFormat == outputFormatJSON {
				enc := json.NewEncoder(os.Stdout)
				err := enc.Encode(results)
				if err != nil {
					return fmt.Errorf("failed to marshal results to JSON: %w", err)
				}
			}

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type scanParams struct {
	requireZeroFindings bool
	localDBFilePath     string
	outputFormat        string
	sbomInput           bool
}

func (p *scanParams) addFlagsTo(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&p.requireZeroFindings, "require-zero", false, "exit 1 if any vulnerabilities are found")
	cmd.Flags().StringVar(&p.localDBFilePath, "local-file-grype-db", "", "import a local grype db file")
	cmd.Flags().StringVarP(&p.outputFormat, "output", "o", "", fmt.Sprintf("output format (%s), defaults to %s", strings.Join([]string{outputFormatOutline, outputFormatJSON}, "|"), outputFormatOutline))
	cmd.Flags().BoolVarP(&p.sbomInput, "sbom", "s", false, "treat input(s) as SBOM(s) of APK(s) instead of as actual APK(s)")
}

type Result struct {
	Target   Target
	Findings []*scan.Finding
}

type Target struct {
	File     string
	FullPath string
}

type findingsTree struct {
	findingsByPackageByLocation map[string]map[string][]*scan.Finding
	packagesByID                map[string]scan.Package
}

func newFindingsTree(findings []*scan.Finding) *findingsTree {
	tree := make(map[string]map[string][]*scan.Finding)
	packagesByID := make(map[string]scan.Package)

	for _, f := range findings {
		loc := f.Package.Location
		packageID := f.Package.ID
		packagesByID[packageID] = f.Package

		if _, ok := tree[loc]; !ok {
			tree[loc] = make(map[string][]*scan.Finding)
		}

		tree[loc][packageID] = append(tree[loc][packageID], f)
	}

	return &findingsTree{
		findingsByPackageByLocation: tree,
		packagesByID:                packagesByID,
	}
}

func (t findingsTree) render() string {
	locations := lo.Keys(t.findingsByPackageByLocation)
	sort.Strings(locations)

	var lines []string
	for i, location := range locations {
		var treeStem, verticalLine string
		if i == len(locations)-1 {
			treeStem = "└── "
			verticalLine = " "
		} else {
			treeStem = "├── "
			verticalLine = "│"
		}

		line := treeStem + fmt.Sprintf("📄 %s", location)
		lines = append(lines, line)

		packageIDs := lo.Keys(t.findingsByPackageByLocation[location])
		packages := lo.Map(packageIDs, func(id string, _ int) scan.Package {
			return t.packagesByID[id]
		})

		sort.SliceStable(packages, func(i, j int) bool {
			return packages[i].Name < packages[j].Name
		})

		for _, pkg := range packages {
			line := fmt.Sprintf(
				"%s       📦 %s %s %s",
				verticalLine,
				pkg.Name,
				pkg.Version,
				styleSubtle.Render("("+pkg.Type+")"),
			)
			lines = append(lines, line)

			findings := t.findingsByPackageByLocation[location][pkg.ID]
			sort.SliceStable(findings, func(i, j int) bool {
				return findings[i].Vulnerability.ID < findings[j].Vulnerability.ID
			})

			for _, f := range findings {
				line := fmt.Sprintf(
					"%s           %s %s%s",
					verticalLine,
					renderSeverity(f.Vulnerability.Severity),
					renderVulnerabilityID(f.Vulnerability),
					renderFixedIn(f.Vulnerability),
				)
				lines = append(lines, line)
			}
		}

		lines = append(lines, verticalLine)
	}

	return strings.Join(lines, "\n")
}

func renderSeverity(severity string) string {
	switch severity {
	case "Negligible":
		return styleNegligible.Render(severity)
	case "Low":
		return styleLow.Render(severity)
	case "Medium":
		return styleMedium.Render(severity)
	case "High":
		return styleHigh.Render(severity)
	case "Critical":
		return styleCritical.Render(severity)
	default:
		return severity
	}
}

func renderVulnerabilityID(vuln scan.Vulnerability) string {
	var cveID string

	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			cveID = alias
			break
		}
	}

	if cveID == "" {
		return hyperlinkVulnerabilityID(vuln.ID)
	}

	return fmt.Sprintf(
		"%s %s",
		hyperlinkVulnerabilityID(cveID),

		styleSubtle.Render(hyperlinkVulnerabilityID(vuln.ID)),
	)
}

var termSupportsHyperlinks = termlink.SupportsHyperlinks()

func hyperlinkVulnerabilityID(id string) string {
	if !termSupportsHyperlinks {
		return id
	}

	switch {
	case strings.HasPrefix(id, "CVE-"):
		return termlink.Link(id, fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", id))

	case strings.HasPrefix(id, "GHSA-"):
		return termlink.Link(id, fmt.Sprintf("https://github.com/advisories/%s", id))
	}

	return id
}

func renderFixedIn(vuln scan.Vulnerability) string {
	if vuln.FixedVersion == "" {
		return ""
	}

	return fmt.Sprintf(" fixed in %s", vuln.FixedVersion)
}

var (
	styleSubtle = lipgloss.NewStyle().Foreground(lipgloss.Color("#999999"))

	styleNegligible = lipgloss.NewStyle().Foreground(lipgloss.Color("#999999"))
	styleLow        = lipgloss.NewStyle().Foreground(lipgloss.Color("#00ff00"))
	styleMedium     = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffff00"))
	styleHigh       = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff9900"))
	styleCritical   = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff0000"))
)
