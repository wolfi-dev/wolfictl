package scanfindings

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/tree"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/vulnid"
	"github.com/wolfi-dev/wolfictl/pkg/cli/styles"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/scan"
)

const noVulnerabilitiesFound = "✅ No vulnerabilities found"

var (
	styleSubtle = lipgloss.NewStyle().Foreground(lipgloss.Color("#999999"))

	styleNegligible = lipgloss.NewStyle().Foreground(lipgloss.Color("#999999"))
	styleLow        = lipgloss.NewStyle().Foreground(lipgloss.Color("#00ff00"))
	styleMedium     = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffff00"))
	styleHigh       = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff9900"))
	styleCritical   = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff0000"))
)

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
		return vulnid.Hyperlink(vuln.ID)
	}

	return fmt.Sprintf(
		"%s %s",
		vulnid.Hyperlink(cveID),

		styleSubtle.Render(vulnid.Hyperlink(vuln.ID)),
	)
}

func renderFixedIn(vuln scan.Vulnerability) string {
	if vuln.FixedVersion == "" {
		return ""
	}

	return fmt.Sprintf(" fixed in %s", vuln.FixedVersion)
}

func renderAdvisoryPathParts(adv *v2.Advisory) []string {
	if adv == nil {
		return nil
	}

	latest := adv.Latest()
	t := time.Time(latest.Timestamp)
	ts := t.Format("2006-01-02T15:04:05Z")

	da := daysAgo(t)

	parts := []string{
		fmt.Sprintf("📝 %s: set to %s %d days ago %s",
			vulnid.Hyperlink(adv.ID),
			styles.Bold().Render(latest.Type),
			da,
			styleSubtle.Render("@ "+ts),
		),
	}

	if note := latest.Note(); note != "" {
		parts = append(parts, styles.Italic().Render(note))
	}

	return parts
}

func daysAgo(t time.Time) int {
	now := time.Now()
	duration := now.Sub(t)
	days := int(duration.Hours() / 24)
	return days
}

func Render(findings []scan.Finding) (string, error) {
	if len(findings) == 0 {
		return noVulnerabilitiesFound, nil
	}

	sort.Stable(scan.Findings(findings))

	t, err := tree.New(findings, func(f scan.Finding) []string {
		pathParts := []string{
			"",
			fmt.Sprintf("📄 %s", f.Package.Location),
			fmt.Sprintf(
				"📦 %s %s %s",
				f.Package.Name,
				f.Package.Version,
				styleSubtle.Render("("+f.Package.Type+")"),
			),
			fmt.Sprintf(
				"%s %s%s",
				renderSeverity(f.Vulnerability.Severity),
				renderVulnerabilityID(f.Vulnerability),
				renderFixedIn(f.Vulnerability),
			),
		}

		if f.Advisory != nil {
			pathParts = append(pathParts, renderAdvisoryPathParts(f.Advisory)...)
		}

		return pathParts
	})
	if err != nil {
		return "", err
	}

	return t.Render(), nil
}
