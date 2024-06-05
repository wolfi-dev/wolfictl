package cli

import (
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/melange/pkg/config"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/cli/styles"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
	"github.com/wolfi-dev/wolfictl/pkg/internal"
	"github.com/wolfi-dev/wolfictl/pkg/versions"
)

const (
	envVarNameForDistroDir     = "WOLFICTL_DISTRO_REPO_DIR"
	envVarNameForAdvisoriesDir = "WOLFICTL_ADVISORIES_REPO_DIR"
)

func cmdAdvisory() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "advisory",
		Aliases:       []string{"adv"},
		SilenceErrors: true,
		Short:         "Commands for consuming and maintaining security advisory data",
	}

	cmd.AddCommand(
		cmdAdvisoryAlias(),
		cmdAdvisoryCopy(),
		cmdAdvisoryCreate(),
		cmdAdvisoryDiff(),
		cmdAdvisoryDiscover(),
		cmdAdvisoryExport(),
		cmdAdvisoryGuide(),
		cmdAdvisoryList(),
		cmdAdvisoryMigrateIDs(),
		cmdAdvisorySecDB(),
		cmdAdvisoryUpdate(),
		cmdAdvisoryValidate(),
	)

	return cmd
}

func resolveDistroDir(cliFlagValue string) string {
	if v := cliFlagValue; v != "" {
		return v
	}

	return os.Getenv(envVarNameForDistroDir)
}

func resolveAdvisoriesDirInput(cliFlagValue string) string {
	if v := cliFlagValue; v != "" {
		return v
	}

	if v := os.Getenv(envVarNameForAdvisoriesDir); v != "" {
		return v
	}

	return ""
}

func renderDetectedDistro(d distro.Distro) string {
	return styles.Secondary().Render("Auto-detected distro: ") + d.Absolute.Name + "\n\n"
}

func resolveTimestamp(ts string) (v2.Timestamp, error) {
	if ts == "now" {
		return v2.Now(), nil
	}

	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return v2.Timestamp{}, fmt.Errorf("unable to parse timestamp: %w", err)
	}

	return v2.Timestamp(t), nil
}

type advisoryRequestParams struct {
	packageName, vuln, eventType, truePositiveNote, falsePositiveNote, falsePositiveType, timestamp, fixedVersion string
}

func (p *advisoryRequestParams) addFlags(cmd *cobra.Command) {
	addPackageFlag(&p.packageName, cmd)
	addVulnFlag(&p.vuln, cmd)

	cmd.Flags().StringVarP(&p.eventType, "type", "t", "", fmt.Sprintf("type of event [%s]", strings.Join(v2.EventTypes, ", ")))
	cmd.Flags().StringVar(&p.truePositiveNote, "tp-note", "", "prose explanation of the true positive (used only for true positives)")
	cmd.Flags().StringVar(&p.falsePositiveNote, "fp-note", "", "prose explanation of the false positive (used only for false positives)")
	cmd.Flags().StringVar(&p.falsePositiveType, "fp-type", "", fmt.Sprintf("type of false positive [%s]", strings.Join(v2.FPTypes, ", ")))
	cmd.Flags().StringVar(&p.timestamp, "timestamp", "now", "timestamp of the event (RFC3339 format)")
	cmd.Flags().StringVar(&p.fixedVersion, "fixed-version", "", "package version where fix was applied (used only for 'fixed' event type)")
}

func (p *advisoryRequestParams) advisoryRequest() (advisory.Request, error) {
	timestamp, err := resolveTimestamp(p.timestamp)
	if err != nil {
		return advisory.Request{}, fmt.Errorf("unable to process timestamp: %w", err)
	}

	req := advisory.Request{
		Package:         p.packageName,
		VulnerabilityID: p.vuln,
		Event: v2.Event{
			Timestamp: timestamp,
			Type:      p.eventType,
			Data:      nil,
		},
	}

	switch req.Event.Type {
	case v2.EventTypeFixed:
		req.Event.Data = v2.Fixed{
			FixedVersion: p.fixedVersion,
		}

	case v2.EventTypeFalsePositiveDetermination:
		req.Event.Data = v2.FalsePositiveDetermination{
			Type: p.falsePositiveType,
			Note: p.falsePositiveNote,
		}

	case v2.EventTypeTruePositiveDetermination:
		req.Event.Data = v2.TruePositiveDetermination{
			Note: p.truePositiveNote,
		}
	}

	return req, nil
}

const (
	flagNamePackage           = "package"
	flagNameVuln              = "vuln"
	flagNameDistroRepoDir     = "distro-repo-dir"
	flagNameAdvisoriesRepoDir = "advisories-repo-dir"
	flagNameNoPrompt          = "no-prompt"
	flagNameNoDistroDetection = "no-distro-detection"
	flagNamePackageRepoURL    = "package-repo-url"
)

func addPackageFlag(val *string, cmd *cobra.Command) {
	cmd.Flags().StringVarP(val, flagNamePackage, "p", "", "package name")
}

func addVulnFlag(val *string, cmd *cobra.Command) {
	cmd.Flags().StringVarP(val, flagNameVuln, "V", "", "vulnerability ID for advisory")
}

func addDistroDirFlag(val *string, cmd *cobra.Command) {
	cmd.Flags().StringVarP(val, flagNameDistroRepoDir, "d", "", "directory containing the distro repository")
}

func addAdvisoriesDirFlag(val *string, cmd *cobra.Command) {
	cmd.Flags().StringVarP(val, flagNameAdvisoriesRepoDir, "a", "", "directory containing the advisories repository")
}

func addNoPromptFlag(val *bool, cmd *cobra.Command) {
	cmd.Flags().BoolVar(val, flagNameNoPrompt, false, "do not prompt the user for input")
}

func addNoDistroDetectionFlag(val *bool, cmd *cobra.Command) {
	cmd.Flags().BoolVar(val, flagNameNoDistroDetection, false, "do not attempt to auto-detect the distro")
}

func addPackageRepoURLFlag(val *string, cmd *cobra.Command) {
	cmd.Flags().StringVarP(val, flagNamePackageRepoURL, "r", "", "URL of the APK package repository")
}

func addVerboseFlag(val *int, cmd *cobra.Command) {
	cmd.Flags().CountVarP(val, "verbose", "v", "logging verbosity (v = info, vv = debug, default is none)")
}

func newLogger(verbosity int) *slog.Logger {
	var h slog.Handler
	switch {
	case verbosity == 1:
		h = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	case verbosity >= 2:
		h = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	default:
		return internal.NopLogger()
	}

	return slog.New(h)
}

func newAllowedFixedVersionsFunc(apkindexes []*apk.APKIndex, buildCfgs *configs.Index[config.Configuration]) func(packageName string) []string {
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
