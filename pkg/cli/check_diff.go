package cli

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/checks"
)

func Diff() *cobra.Command {
	o := checks.NewDiff()
	cmd := &cobra.Command{
		Use:               "diff",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		SilenceErrors:     true,
		Short:             "Create a diff comparing proposed apk changes following a melange build, to the latest available in an APKINDEX",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.Diff()
		},
	}

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	cmd.Flags().StringVar(&o.Dir, "dir", cwd, "directory the command is executed from and will contain the resulting diff.log file")
	cmd.Flags().StringVar(&o.PackagesDir, "packages-dir", filepath.Join(cwd, "packages"), "directory containing new packages")
	cmd.Flags().StringVarP(&o.PackageListFilename, "package-list-file", "", "packages.log", "name of the package to compare")
	cmd.Flags().StringVarP(&o.ApkIndexURL, "apk-index-url", "", "https://packages.wolfi.dev/os/aarch64/APKINDEX.tar.gz", "apk-index-url used to get existing apks.  Defaults to wolfi")

	return cmd
}
