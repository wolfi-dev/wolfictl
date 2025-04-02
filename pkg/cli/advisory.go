package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/melange/pkg/config"
	yamutil "github.com/chainguard-dev/yam/pkg/util"
	"github.com/chainguard-dev/yam/pkg/yam/formatted"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/cli/styles"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
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
		cmdAdvisoryID(),
		cmdAdvisoryList(),
		cmdAdvisoryMigrateIDs(),
		cmdAdvisoryOSV(),
		cmdAdvisoryRebase(),
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

func addFlagsForAdvisoryRequestParams(p *advisory.RequestParams, cmd *cobra.Command) {
	addMultiPackageFlag(&p.PackageNames, cmd)
	addMultiVulnFlag(&p.Vulns, cmd)

	cmd.Flags().StringVarP(&p.EventType, "type", "t", "", fmt.Sprintf("type of event [%s]", strings.Join(v2.EventTypes, ", ")))
	cmd.Flags().StringVar(&p.Note, "note", "", "prose explanation to attach to the event data (can be used with any event type)")
	cmd.Flags().StringVar(&p.TruePositiveNote, "tp-note", "", "prose explanation of the true positive (used only for true positives)")
	_ = cmd.Flags().MarkDeprecated("tp-note", "use --note instead") //nolint:errcheck
	cmd.Flags().StringVar(&p.FalsePositiveNote, "fp-note", "", "prose explanation of the false positive (used only for false positives)")
	_ = cmd.Flags().MarkDeprecated("fp-note", "use --note instead") //nolint:errcheck
	cmd.Flags().StringVar(&p.FalsePositiveType, "fp-type", "", fmt.Sprintf("type of false positive [%s]", strings.Join(v2.FPTypes, ", ")))
	cmd.Flags().StringVar(&p.Timestamp, "timestamp", "now", "timestamp of the event (RFC3339 format)")
	cmd.Flags().StringVar(&p.FixedVersion, "fixed-version", "", "package version where fix was applied (used only for 'fixed' event type)")
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

func addMultiPackageFlag(val *[]string, cmd *cobra.Command) {
	cmd.Flags().StringSliceVarP(val, flagNamePackage, "p", nil, "package names")
}

func addVulnFlag(val *string, cmd *cobra.Command) {
	cmd.Flags().StringVarP(val, flagNameVuln, "V", "", "vulnerability ID for advisory")
}

func addMultiVulnFlag(val *[]string, cmd *cobra.Command) {
	cmd.Flags().StringSliceVarP(val, flagNameVuln, "V", nil, "vulnerability IDs for advisory")
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

// getYamEncodeOptions does a "best effort" retrieval of the yam encode options.
// If no yam config is present in the given directory, no error is returned, and
// a set of default options are returned. An error is only returned if there is
// a problem reading the (present) yam config file.
func getYamEncodeOptions(dir string) (formatted.EncodeOptions, error) {
	defaultOpts := formatted.EncodeOptions{}

	yamCfgPath := filepath.Join(dir, yamutil.ConfigFileName)
	yamCfgFile, err := os.Open(yamCfgPath)
	if err != nil {
		return defaultOpts, nil
	}

	readOpts, err := formatted.ReadConfigFrom(yamCfgFile)
	if err != nil {
		return defaultOpts, fmt.Errorf("reading yam config from %q: %w", yamCfgPath, err)
	}

	return *readOpts, nil
}

func doesRequestRepeatEventType(ctx context.Context, g advisory.Getter, req advisory.Request) (bool, error) {
	pkgAdvs, err := g.Advisories(ctx, req.Package)
	if err != nil {
		return false, fmt.Errorf("getting advisories for package %q: %w", req.Package, err)
	}
	if len(pkgAdvs) == 0 {
		return false, nil
	}

	pkgAdv := advisory.MatchToRequest(pkgAdvs, req)
	if pkgAdv != nil {
		// We found an existing advisory for this package.
		// Check if the latest event type is the same as the one we're adding.
		if pkgAdv.Latest().Type == req.Event.Type {
			return true, nil
		}
	}

	return false, nil
}
