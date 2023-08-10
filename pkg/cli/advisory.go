package cli

import (
	"fmt"
	"os"
	"sort"
	"time"

	"chainguard.dev/melange/pkg/config"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/cli/styles"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
	"github.com/wolfi-dev/wolfictl/pkg/versions"
	"gitlab.alpinelinux.org/alpine/go/repository"
)

const (
	envVarNameForDistroDir     = "WOLFICTL_DISTRO_REPO_DIR"
	envVarNameForAdvisoriesDir = "WOLFICTL_ADVISORIES_REPO_DIR"
)

func Advisory() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "advisory",
		Aliases:       []string{"adv"},
		SilenceErrors: true,
		Short:         "Utilities for viewing and modifying Wolfi advisory data",
	}

	cmd.AddCommand(AdvisoryList())
	cmd.AddCommand(AdvisoryCreate())
	cmd.AddCommand(AdvisoryUpdate())
	cmd.AddCommand(AdvisoryDiscover())
	cmd.AddCommand(AdvisoryDB())
	cmd.AddCommand(AdvisoryValidate())
	cmd.AddCommand(AdvisoryExport())

	return cmd
}

func resolveDistroDir(cliFlagValue string) string {
	if v := cliFlagValue; v != "" {
		return v
	}

	return os.Getenv(envVarNameForDistroDir)
}

func resolveAdvisoriesDir(cliFlagValue string) string {
	if v := cliFlagValue; v != "" {
		return v
	}

	if v := os.Getenv(envVarNameForAdvisoriesDir); v != "" {
		return v
	}

	return ""
}

func renderDetectedDistro(d distro.Distro) string {
	return styles.Secondary().Render("Auto-detected distro: ") + d.Name + "\n\n"
}

func resolveTimestamp(ts string) (time.Time, error) {
	if ts == "now" {
		return time.Now(), nil
	}

	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return time.Time{}, fmt.Errorf("unable to parse timestamp: %w", err)
	}

	return t, nil
}

type advisoryRequestParams struct {
	packageName, vuln, status, action, impact, justification, timestamp, fixedVersion string
}

func (p *advisoryRequestParams) addFlags(cmd *cobra.Command) {
	addPackageFlag(&p.packageName, cmd)
	addVulnFlag(&p.vuln, cmd)

	cmd.Flags().StringVarP(&p.status, "status", "s", "", "status for VEX statement")
	cmd.Flags().StringVar(&p.action, "action", "", "action statement for VEX statement (used only for affected status)")
	cmd.Flags().StringVar(&p.impact, "impact", "", "impact statement for VEX statement (used only for not_affected status)")
	cmd.Flags().StringVar(&p.justification, "justification", "", "justification for VEX statement (used only for not_affected status)")
	cmd.Flags().StringVar(&p.timestamp, "timestamp", "now", "timestamp for VEX statement")
	cmd.Flags().StringVar(&p.fixedVersion, "fixed-version", "", "package version where fix was applied (used only for fixed status)")
}

func (p *advisoryRequestParams) advisoryRequest() (advisory.Request, error) {
	timestamp, err := resolveTimestamp(p.timestamp)
	if err != nil {
		return advisory.Request{}, fmt.Errorf("unable to process timestamp: %w", err)
	}

	return advisory.Request{
		Package:       p.packageName,
		Vulnerability: p.vuln,
		Status:        vex.Status(p.status),
		Action:        p.action,
		Impact:        p.impact,
		Justification: vex.Justification(p.justification),
		Timestamp:     timestamp,
		FixedVersion:  p.fixedVersion,
	}, nil
}

func addPackageFlag(val *string, cmd *cobra.Command) {
	cmd.Flags().StringVarP(val, "package", "p", "", "package name")
}

func addVulnFlag(val *string, cmd *cobra.Command) {
	cmd.Flags().StringVarP(val, "vuln", "V", "", "vulnerability ID for advisory")
}

func addDistroDirFlag(val *string, cmd *cobra.Command) {
	cmd.Flags().StringVarP(val, "distro-repo-dir", "d", "", fmt.Sprintf("directory containing the distro repository (can also be set with environment variable `%s`)", envVarNameForDistroDir))
}

func addAdvisoriesDirFlag(val *string, cmd *cobra.Command) {
	cmd.Flags().StringVarP(val, "advisories-repo-dir", "a", "", fmt.Sprintf("directory containing the advisories repository (can also be set with environment variable `%s`)", envVarNameForAdvisoriesDir))
}

func addNoPromptFlag(val *bool, cmd *cobra.Command) {
	cmd.Flags().BoolVar(val, "no-prompt", false, "do not prompt the user for input")
}

func addNoDistroDetectionFlag(val *bool, cmd *cobra.Command) {
	cmd.Flags().BoolVar(val, "no-distro-detection", false, "do not attempt to auto-detect the distro")
}

func newAllowedFixedVersionsFunc(apkindexes []*repository.ApkIndex, buildCfgs *configs.Index[config.Configuration]) func(packageName string) []string {
	return func(packageName string) []string {
		allowedVersionSet := make(map[string]struct{})

		// Get published versions using APKINDEX data.

		for _, apkindex := range apkindexes {
			for _, pkg := range apkindex.Packages {
				if pkg.Name == packageName {
					allowedVersionSet[pkg.Version] = struct{}{}
				}
			}
		}

		// Also ensure the currently defined version is included in the set, even if it's not been published yet.

		pkg := buildCfgs.Select().WhereName(packageName).Configurations()[0].Package
		currentVersion := fmt.Sprintf("%s-r%d", pkg.Version, pkg.Epoch)
		allowedVersionSet[currentVersion] = struct{}{}

		allowedVersions := lo.Keys(allowedVersionSet)
		sort.Sort(versions.ByLatestStrings(allowedVersions))

		return allowedVersions
	}
}
