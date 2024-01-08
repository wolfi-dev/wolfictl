package cli

import (
	"errors"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/gh"
)

func Release() *cobra.Command {
	releaseOpts := gh.NewReleaseOptions()

	cmd := &cobra.Command{
		Use:               "release",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		Short:             "Performs a GitHub release using git tags to calculate the release version",
		Long: `Performs a GitHub release using git tags to calculate the release version

Examples:

wolfictl gh release --bump-major
wolfictl gh release --bump-minor
wolfictl gh release --bump-patch
wolfictl gh release --bump-prerelease-with-prefix rc
`,
		Args: cobra.RangeArgs(0, 0),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !releaseOpts.BumpMajor &&
				!releaseOpts.BumpMinor &&
				!releaseOpts.BumpPatch &&
				releaseOpts.BumpPrereleaseWithPrefix == "" {
				return errors.New("missing flag to bump release version")
			}

			return releaseOpts.Release()
		},
	}

	cmd.Flags().BoolVar(&releaseOpts.BumpMajor, "bump-major", false, "bumps the major release version")
	cmd.Flags().BoolVar(&releaseOpts.BumpMinor, "bump-minor", false, "bumps the minor release version")
	cmd.Flags().BoolVar(&releaseOpts.BumpPatch, "bump-patch", false, "bumps the patch release version")
	cmd.Flags().StringVar(&releaseOpts.BumpPrereleaseWithPrefix, "bump-prerelease-with-prefix", "", "bumps the prerelease version using the supplied prefix, if no existing prerelease exists the patch version is also bumped to align with semantic versioning")
	cmd.Flags().StringVar(&releaseOpts.Dir, "dir", ".", "directory containing the cloned github repository to release")

	return cmd
}
