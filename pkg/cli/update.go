package cli

import (
	"context"
	"fmt"
	"net/url"
	"os"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/update"
)

type options struct {
	packageNames           []string
	pullRequestBaseBranch  string
	pullRequestTitle       string
	dryRun                 bool
	githubReleaseQuery     bool
	releaseMonitoringQuery bool
	useGitSign             bool
	createIssues           bool
	issueLabels            []string
	maxRetries             int
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
	cmd.Flags().BoolVar(&o.githubReleaseQuery, "github-release-query", true, "query the GitHub graphql API for latest releases")
	cmd.Flags().BoolVar(&o.releaseMonitoringQuery, "release-monitoring-query", true, "query https://release-monitoring.org/ API for latest releases")
	cmd.Flags().StringArrayVar(&o.packageNames, "package-name", []string{}, "Optional: provide a specific package name to check for updates rather than searching all packages in a repo URI")
	cmd.Flags().StringVar(&o.pullRequestBaseBranch, "pull-request-base-branch", "main", "base branch to create a pull request against")
	cmd.Flags().StringVar(&o.pullRequestTitle, "pull-request-title", "%s/%s package update", "the title to use when creating a pull request")
	cmd.Flags().BoolVar(&o.useGitSign, "use-gitsign", false, "enable gitsign to sign the git commits")
	cmd.Flags().BoolVar(&o.createIssues, "create-issues", true, "creates GitHub Issues for failed package updates")
	cmd.Flags().StringArrayVar(&o.issueLabels, "github-labels", []string{}, "Optional: provide a list of labels to apply to updater generated issues and pull requests")
	cmd.Flags().IntVar(&o.maxRetries, "max-retries", 3, "maximum number of retries for failed package updates")

	cmd.AddCommand(
		Package(),
	)

	return cmd
}

func (o options) UpdateCmd(ctx context.Context, repoURI string) error {
	updateContext := update.New()

	if !o.dryRun && os.Getenv("GITHUB_TOKEN") == "" {
		return errors.New("no GITHUB_TOKEN token found")
	}

	if _, err := url.ParseRequestURI(repoURI); err != nil {
		return fmt.Errorf("failed to parse URI %s: %w", repoURI, err)
	}
	updateContext.PackageNames = o.packageNames
	updateContext.RepoURI = repoURI
	updateContext.DryRun = o.dryRun
	updateContext.PullRequestBaseBranch = o.pullRequestBaseBranch
	updateContext.PullRequestTitle = o.pullRequestTitle
	updateContext.ReleaseMonitoringQuery = o.releaseMonitoringQuery
	updateContext.GithubReleaseQuery = o.githubReleaseQuery
	updateContext.UseGitSign = o.useGitSign
	updateContext.CreateIssues = o.createIssues
	updateContext.IssueLabels = o.issueLabels
	updateContext.MaxRetries = o.maxRetries
	if err := updateContext.Update(ctx); err != nil {
		return fmt.Errorf("creating updates: %w", err)
	}

	return nil
}
