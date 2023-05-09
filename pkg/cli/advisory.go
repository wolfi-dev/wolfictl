package cli

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/advisory/sync"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	advisoryconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/advisory"
)

const (
	envVarNameForDistroDir     = "WOLFICTL_DISTRO_REPO_DIR"
	envVarNameForAdvisoriesDir = "WOLFICTL_ADVISORIES_REPO_DIR"
	defaultAdvisoriesRepoDir   = "."
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
	cmd.AddCommand(AdvisorySyncSecfixes())
	cmd.AddCommand(AdvisoryDiscover())
	cmd.AddCommand(AdvisoryDB())

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

func doFollowupSync(selection configs.Selection[advisoryconfigs.Document]) error {
	needs, err := sync.DetermineNeeds(selection)

	if err != nil {
		return fmt.Errorf("unable to sync secfixes data for advisory: %w", err)
	}

	unmetNeeds := sync.Unmet(needs)

	if len(unmetNeeds) == 0 {
		log.Printf("INFO: No secfixes data needed to be added from this advisory. Secfixes data is in sync. 👍")
		return nil
	}

	for _, n := range unmetNeeds {
		err := n.Resolve()
		if err != nil {
			return fmt.Errorf("unable to sync secfixes data for advisory: %w", err)
		}
	}

	return nil
}

type advisoryRequestParams struct {
	packageName, vuln, status, action, impact, justification, timestamp, fixedVersion string
	sync                                                                              bool
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
	cmd.Flags().BoolVar(&p.sync, "sync", false, "synchronize secfixes data immediately after updating advisory")
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
