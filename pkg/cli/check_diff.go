package cli

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/apk"
	"github.com/wolfi-dev/wolfictl/pkg/checks"
)

func Diff() *cobra.Command {
	o := checks.NewDiff()
	var packageListFile string
	cmd := &cobra.Command{
		Use:               "diff",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		SilenceErrors:     true,
		Short:             "Create a diff comparing proposed apk changes following a melange build, to the latest available in an APKINDEX",
		Args:              cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			arch := ""
			switch runtime.GOARCH {
			case "amd64":
				arch = "x86_64"
			case "arm64":
				arch = "aarch64"
			default:
				return fmt.Errorf("architecture %s not supported", runtime.GOARCH)
			}
			o.ApkIndexURL = fmt.Sprintf(o.ApkIndexURL, arch)

			apkContext := apk.New(o.Client, o.ApkIndexURL)
			existingPackages, err := apkContext.GetApkPackages()
			if err != nil {
				return fmt.Errorf("failed to get APK packages from URL %s: %w", o.ApkIndexURL, err)
			}

			// get a list of new package names that have recently been built
			newPackages, err := checks.GetNewPackages(packageListFile)
			if err != nil {
				return fmt.Errorf("failed to get new packages: %w", err)
			}

			return o.Diff(cmd.Context(), existingPackages, newPackages)
		},
	}

	cwd := "."

	cmd.Flags().StringVar(&o.Dir, "dir", cwd, "directory the command is executed from and will contain the resulting diff.log file")
	cmd.Flags().StringVar(&o.PackagesDir, "packages-dir", filepath.Join(cwd, "packages"), "directory containing new packages")
	cmd.Flags().StringVarP(&packageListFile, "package-list-file", "", "packages.log", "name of the package to compare")
	cmd.Flags().StringVarP(&o.ApkIndexURL, "apk-index-url", "", "https://packages.wolfi.dev/os/%s/APKINDEX.tar.gz", "apk-index-url used to get existing apks.  Defaults to wolfi")

	return cmd
}
