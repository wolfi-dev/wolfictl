package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/scan"
)

func Scan() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan <path/to/apk>",
		Short: "Scan an apk file for vulnerabilities",
		Args:  cobra.ExactArgs(1), // TODO: support scanning multiple apks!
		RunE: func(cmd *cobra.Command, args []string) error {
			apkFilePath := args[0]

			apkFile, err := os.Open(apkFilePath)
			if err != nil {
				return fmt.Errorf("failed to open apk file: %w", err)
			}
			defer apkFile.Close()

			findings, err := scan.APK(apkFile)
			if err != nil {
				return err
			}

			if len(findings) == 0 {
				fmt.Println("No vulnerabilities found")
			} else {
				lineItems := lo.Map(findings, func(f *scan.Finding, _ int) string {
					return renderFinding(*f)
				})

				fmt.Println(strings.Join(lineItems, "\n"))
			}

			return nil
		},
	}

	return cmd
}

func renderFinding(f scan.Finding) string {
	return fmt.Sprintf(
		"%s (%s) @ %s %s %s (%s): %s",
		f.Package,
		f.Type,
		f.Version,
		styleSubtle.Render("matched to"),
		f.VulnerabilityID,
		strings.Join(f.Aliases, ", "),
		renderSeverity(f.Severity),
	)
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

var (
	styleSubtle = lipgloss.NewStyle().Foreground(lipgloss.Color("#999999"))

	styleNegligible = lipgloss.NewStyle().Foreground(lipgloss.Color("#999999"))
	styleLow        = lipgloss.NewStyle().Foreground(lipgloss.Color("#00ff00"))
	styleMedium     = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffff00"))
	styleHigh       = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff9900"))
	styleCritical   = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff0000"))
)
