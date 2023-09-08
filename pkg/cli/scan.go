package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"

	sbomSyft "github.com/anchore/syft/syft/sbom"
	"github.com/charmbracelet/lipgloss"
	"github.com/samber/lo"
	"github.com/savioxavier/termlink"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/sbom"
	"github.com/wolfi-dev/wolfictl/pkg/scan"
	"golang.org/x/exp/slices"
)

func cmdScan() *cobra.Command {
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

			// Validate inputs

			var advisoryCfgs *configs.Index[v2.Document]

			if !slices.Contains(validOutputFormats, p.outputFormat) {
				return fmt.Errorf(
					"invalid output format %q, must be one of [%s]",
					p.outputFormat,
					strings.Join(validOutputFormats, ", "),
				)
			}

			if p.advisoryFilterSet != "" {
				if !slices.Contains(scan.ValidAdvisoriesSets, p.advisoryFilterSet) {
					return fmt.Errorf(
						"invalid advisory filter set %q, must be one of [%s]",
						p.advisoryFilterSet,
						strings.Join(scan.ValidAdvisoriesSets, ", "),
					)
				}

				if p.advisoriesRepoDir == "" {
					return errors.New("advisory-based filtering requested, but no advisories repo dir was provided")
				}

				advisoriesFsys := rwos.DirFS(p.advisoriesRepoDir)
				var err error
				advisoryCfgs, err = v2.NewIndex(advisoriesFsys)
				if err != nil {
					return fmt.Errorf("failed to load advisory documents: %w", err)
				}
			}

			// Do a scan for each arg

			var scans []inputScan

			for _, input := range args {
				scannedInput, err := scanInput(input, p)
				if err != nil {
					return err
				}

				// If requested, filter scan results using advisories

				if set := p.advisoryFilterSet; set != "" {
					findings, err := scan.FilterWithAdvisories(scannedInput.Result, advisoryCfgs, set)
					if err != nil {
						return fmt.Errorf("failed to filter scan results with advisories during scan of %q: %w", input, err)
					}

					scannedInput.Result.Findings = findings
				}

				scans = append(scans, *scannedInput)

				// Handle CLI options

				findings := scannedInput.Result.Findings
				if p.outputFormat == outputFormatOutline {
					// Print output immediately

					if len(findings) == 0 {
						fmt.Println("✅ No vulnerabilities found")
					} else {
						tree := newFindingsTree(findings)
						fmt.Println(tree.render())
					}
				}
				if p.requireZeroFindings && len(findings) > 0 {
					// Exit with error immediately if any vulnerabilities are found
					return fmt.Errorf("more than 0 vulnerabilities found")
				}
			}

			if p.outputFormat == outputFormatJSON {
				enc := json.NewEncoder(os.Stdout)
				err := enc.Encode(scans)
				if err != nil {
					return fmt.Errorf("failed to marshal scans to JSON: %w", err)
				}
			}

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

func scanInput(inputFilePath string, p *scanParams) (*inputScan, error) {
	if inputFilePath == "-" {
		// Read stdin into a temp file.
		t, err := os.CreateTemp("", "wolfictl-scan-")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp file for stdin: %w", err)
		}
		if _, err := io.Copy(t, os.Stdin); err != nil {
			return nil, err
		}
		if err := t.Close(); err != nil {
			return nil, err
		}
		fmt.Fprintln(os.Stderr, "Will process from stdin")
		inputFilePath = t.Name()
	} else if strings.HasPrefix(inputFilePath, "https://") {
		// Fetch the remote URL into a temp file.
		t, err := os.CreateTemp("", "wolfictl-scan-")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp file for remote: %w", err)
		}
		resp, err := http.Get(inputFilePath) //nolint:gosec
		if err != nil {
			return nil, fmt.Errorf("failed to download from remote: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			all, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("failed to download from remote (%d): %s", resp.StatusCode, string(all))
		}
		if _, err := io.Copy(t, resp.Body); err != nil {
			return nil, err
		}
		if err := t.Close(); err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "Will process: %s\n", inputFilePath)
		inputFilePath = t.Name()
	} else {
		fmt.Fprintf(os.Stderr, "Will process: %s\n", path.Base(inputFilePath))
	}
	inputFile, err := os.Open(inputFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	// Get SBOM of the APK

	var apkSBOM io.Reader
	if p.sbomInput {
		apkSBOM = inputFile
	} else {
		var s *sbomSyft.SBOM
		if p.disableSBOMCache {
			s, err = sbom.Generate(inputFilePath, inputFile, p.distro)
		} else {
			s, err = sbom.CachedGenerate(inputFilePath, inputFile, p.distro)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to generate SBOM: %w", err)
		}

		reader, err := sbom.ToSyftJSON(s)
		if err != nil {
			return nil, fmt.Errorf("failed to convert SBOM to Syft JSON: %w", err)
		}
		apkSBOM = reader
	}

	// Do vulnerability scan!

	result, err := scan.APKSBOM(apkSBOM, p.localDBFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to scan APK using %q: %w", inputFilePath, err)
	}

	is := &inputScan{
		InputFile: inputFilePath,
		Result:    result,
	}

	return is, nil
}

type scanParams struct {
	requireZeroFindings bool
	localDBFilePath     string
	outputFormat        string
	sbomInput           bool
	distro              string
	advisoryFilterSet   string
	advisoriesRepoDir   string
	disableSBOMCache    bool
}

func (p *scanParams) addFlagsTo(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&p.requireZeroFindings, "require-zero", false, "exit 1 if any vulnerabilities are found")
	cmd.Flags().StringVar(&p.localDBFilePath, "local-file-grype-db", "", "import a local grype db file")
	cmd.Flags().StringVarP(&p.outputFormat, "output", "o", "", fmt.Sprintf("output format (%s), defaults to %s", strings.Join(validOutputFormats, "|"), outputFormatOutline))
	cmd.Flags().BoolVarP(&p.sbomInput, "sbom", "s", false, "treat input(s) as SBOM(s) of APK(s) instead of as actual APK(s)")
	cmd.Flags().StringVar(&p.distro, "distro", "wolfi", "distro to use during vulnerability matching")
	cmd.Flags().StringVarP(&p.advisoryFilterSet, "advisory-filter", "f", "", fmt.Sprintf("exclude vulnerability matches that are referenced from the specified set of advisories (%s)", strings.Join(scan.ValidAdvisoriesSets, "|")))
	cmd.Flags().StringVarP(&p.advisoriesRepoDir, "advisories-repo-dir", "a", "", "local directory for advisory data")
	cmd.Flags().BoolVar(&p.disableSBOMCache, "disable-sbom-cache", false, "don't use the SBOM cache")
}

const (
	outputFormatOutline = "outline"
	outputFormatJSON    = "json"
)

var validOutputFormats = []string{outputFormatOutline, outputFormatJSON}

type inputScan struct {
	InputFile string
	Result    *scan.Result
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
