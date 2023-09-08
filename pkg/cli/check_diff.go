package cli

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/checks"
)

func Diff() *cobra.Command {
	o := checks.NewDiff()
	var apkIndexURL string
	cmd := &cobra.Command{
		Use:               "diff",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		SilenceErrors:     true,
		Short:             "Create a diff comparing proposed apk changes following a melange build, to the latest available in an APKINDEX",
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
			o.ApkIndexURL = fmt.Sprintf(apkIndexURL, arch)

			return o.Diff()
		},
	}

	cwd := "."

	cmd.Flags().StringVar(&o.Dir, "dir", cwd, "directory the command is executed from and will contain the resulting diff.log file")
	cmd.Flags().StringVar(&o.PackagesDir, "packages-dir", filepath.Join(cwd, "packages"), "directory containing new packages")
	cmd.Flags().StringVarP(&o.PackageListFilename, "package-list-file", "", "packages.log", "name of the package to compare")
	cmd.Flags().StringVarP(&apkIndexURL, "apk-index-url", "", "https://packages.wolfi.dev/os/%s/APKINDEX.tar.gz", "apk-index-url used to get existing apks.  Defaults to wolfi")

	return cmd
}
