package cli

import (
	"os"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/update"
)

func Package() *cobra.Command {
	o := update.NewPackageOptions()

	cmd := &cobra.Command{
		Use:     "package",
		Short:   "Proposes a single melange package update via a pull request",
		Long:    `"Proposes a single melange package update via a pull request".`,
		Example: `wolfictl update package cheese --version v1.2.3 --target-repo https://github.com/wolfi-dev/os`,
		Args:    cobra.RangeArgs(1, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !o.DryRun && os.Getenv("GITHUB_TOKEN") == "" {
				return errors.New("no GITHUB_TOKEN token found")
			}

			o.PackageName = args[0]
			return o.UpdatePackageCmd(cmd.Context())
		},
	}

	cmd.Flags().BoolVar(&o.DryRun, "dry-run", false, "prints proposed package updates rather than creating a pull request")
	cmd.Flags().BoolVar(&o.Advisories, "sec-fixes", true, "checks commit messages since last release, for `fixes: CVE###` and generates melange security advisories")
	cmd.Flags().StringVar(&o.PullRequestBaseBranch, "pull-request-base-branch", "main", "base branch to create a pull request against")
	cmd.Flags().StringVar(&o.TargetRepo, "target-repo", "https://github.com/wolfi-dev/os", "target git repository containing melange configuration to update")
	cmd.Flags().StringVar(&o.Version, "version", "", "version to bump melange package to")
	cmd.Flags().StringVar(&o.Epoch, "epoch", "0", "the epoch used to identify fix, defaults to 0 as this command is expected to run in a release pipeline that's creating a new version so epoch will be 0")
	cmd.Flags().BoolVar(&o.UseGitSign, "use-gitsign", false, "enable gitsign to sign the git commits")

	return cmd
}
