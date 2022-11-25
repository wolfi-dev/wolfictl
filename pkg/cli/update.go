package cli

import (
	"context"
	"net/url"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wupdater/pkg/update"
)

type options struct {
	packageName string
	//repoURI     string
	batch  bool
	dryRun bool
}

func Update() *cobra.Command {
	o := &options{}
	cmd := &cobra.Command{
		Use:     "update",
		Short:   "Proposes melange package update(s) via a pull request",
		Long:    `"Proposes melange package update(s) via a pull request".`,
		Example: `  wupdater update https://github.com/wolfi-dev/os`,
		Args:    cobra.RangeArgs(1, 1),
		RunE: func(cmd *cobra.Command, args []string) error {

			return o.UpdateCmd(cmd.Context(), args[0])
		},
	}

	cmd.Flags().BoolVar(&o.dryRun, "dry-run", false, "prints proposed package updates rather than creating a pull request")
	cmd.Flags().BoolVar(&o.dryRun, "batch", true, "creates a single pull request with package updates rather than individual pull request per package update")
	//cmd.Flags().StringVar(&o.repoURI, "repo-uri", "https://github.com/wolfi-dev/os", "URI to use for querying packages and proposing updates to")
	cmd.Flags().StringVar(&o.packageName, "package-name", "", "Optional: provide a specific package name to check for updates rather than searching all packages in a repo URI")

	return cmd
}

func (o options) UpdateCmd(ctx context.Context, repoURI string) error {
	context, err := update.New()
	if err != nil {
		return errors.Wrap(err, "initialising update command")
	}

	_, err = url.ParseRequestURI(repoURI)
	if err != nil {
		return errors.Wrapf(err, "failed to parse URI %s", repoURI)
	}
	context.PackageName = o.packageName
	context.RepoURI = repoURI
	context.DryRun = o.dryRun
	context.Batch = o.batch

	err = context.Update()
	if err != nil {
		return errors.Wrapf(err, "creating updates")
	}

	return nil
}
