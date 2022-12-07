package cli

import (
	"context"
	"net/url"
	"os"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/update"
)

type options struct {
	packageName           string
	pullRequestBaseBranch string
	pullRequestTitle      string
	dataMapperURL         string
	batch                 bool
	dryRun                bool
}

func Update() *cobra.Command {
	o := &options{}
	cmd := &cobra.Command{
		Use:     "update",
		Short:   "Proposes melange package update(s) via a pull request",
		Long:    `"Proposes melange package update(s) via a pull request".`,
		Example: `  wolfictl update https://github.com/wolfi-dev/os`,
		Args:    cobra.RangeArgs(1, 1),
		RunE: func(cmd *cobra.Command, args []string) error {

			return o.UpdateCmd(cmd.Context(), args[0])
		},
	}

	cmd.Flags().BoolVar(&o.dryRun, "dry-run", false, "prints proposed package updates rather than creating a pull request")
	cmd.Flags().BoolVar(&o.batch, "batch", false, "creates a single pull request with package updates rather than individual pull request per package update")
	cmd.Flags().StringVar(&o.packageName, "package-name", "", "Optional: provide a specific package name to check for updates rather than searching all packages in a repo URI")
	cmd.Flags().StringVar(&o.pullRequestBaseBranch, "pull-request-base-branch", "main", "base branch to create a pull request against")
	cmd.Flags().StringVar(&o.pullRequestTitle, "pull-request-title", "%s package update", "the title to use when creating a pull request")
	cmd.Flags().StringVar(&o.dataMapperURL, "data-mapper-url", "https://raw.githubusercontent.com/rawlingsj/wup-mapper/main/README.md", "URL to use for mapping packages to source update service")

	return cmd
}

func (o options) UpdateCmd(ctx context.Context, repoURI string) error {
	context, err := update.New()
	if err != nil {
		return errors.Wrap(err, "initialising update command")
	}

	if !o.dryRun && os.Getenv("GITHUB_TOKEN") == "" {
		return errors.New("no GITHUB_TOKEN token found")
	}

	_, err = url.ParseRequestURI(repoURI)
	if err != nil {
		return errors.Wrapf(err, "failed to parse URI %s", repoURI)
	}
	context.PackageName = o.packageName
	context.RepoURI = repoURI
	context.DataMapperURL = o.dataMapperURL
	context.DryRun = o.dryRun
	context.Batch = o.batch
	context.PullRequestBaseBranch = o.pullRequestBaseBranch
	context.PullRequestTitle = o.pullRequestTitle

	err = context.Update()
	if err != nil {
		return errors.Wrapf(err, "creating updates")
	}

	return nil
}
