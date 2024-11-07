package cli

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/apk"
	"github.com/wolfi-dev/wolfictl/pkg/checks"
)

func SoName() *cobra.Command {
	o := checks.NewSoName()
	var apkIndexURL, packageListFile string
	cmd := &cobra.Command{
		Use:               "so-name",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		SilenceErrors:     true,
		Short:             "Check so name files have not changed in upgrade",
		Args:              cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			apkContext := apk.New(o.Client, apkIndexURL)
			existingPackages, err := apkContext.GetApkPackages()
			if err != nil {
				return fmt.Errorf("failed to get APK packages from URL %s: %w", apkIndexURL, err)
			}

			// get a list of new package names that have recently been built
			newPackages, err := checks.GetNewPackages(packageListFile)
			if err != nil {
				return fmt.Errorf("failed to get new packages: %w", err)
			}

			report := o.CheckSoName(cmd.Context(), existingPackages, newPackages)
			if len(report) > 0 {
				return fmt.Errorf("so name check failed")
			}
			return nil
		},
	}

	cwd := "."

	cmd.Flags().StringVarP(&o.Dir, "directory", "d", ".", "directory containing melange configs")
	cmd.Flags().StringVar(&o.PackagesDir, "packages-dir", filepath.Join(cwd, "packages"), "directory containing new packages")
	cmd.Flags().StringVarP(&packageListFile, "package-list-file", "", "packages.log", "name of the package to compare")
	cmd.Flags().StringVarP(&apkIndexURL, "apk-index-url", "", "https://packages.wolfi.dev/os/aarch64/APKINDEX.tar.gz", "apk-index-url used to get existing apks.  Defaults to wolfi")

	return cmd
}
