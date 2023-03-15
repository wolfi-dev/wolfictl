package cli

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/checks"
)

func SoName() *cobra.Command {
	o := checks.NewSoName()
	cmd := &cobra.Command{
		Use:               "so-name",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		SilenceErrors:     true,
		Short:             "Check so name files have not changed in upgrade",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.CheckSoName()
		},
	}

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	cmd.Flags().StringVarP(&o.Dir, "directory", "d", ".", "directory containing melange configs")
	cmd.Flags().StringVar(&o.PackagesDir, "packages-dir", filepath.Join(cwd, "packages"), "directory containing new packages")
	cmd.Flags().StringVarP(&o.PackageListFilename, "package-list-file", "", "packages.log", "name of the package to compare")
	cmd.Flags().StringArrayVarP(&o.PackageNames, "package-name", "", []string{}, "override using package-list-file and specify a single package name to compare")
	cmd.Flags().StringVarP(&o.ApkIndexURL, "apk-index-url", "", "https://packages.wolfi.dev/os/aarch64/APKINDEX.tar.gz", "apk-index-url used to get existing apks.  Defaults to wolfi")

	return cmd
}
