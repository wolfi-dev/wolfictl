package cli

import (
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/go-github/v58/github"

	http2 "github.com/wolfi-dev/wolfictl/pkg/http"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/gh"
	wgit "github.com/wolfi-dev/wolfictl/pkg/git"
)

func Issues() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "issues",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		Short:             "Issues garbage collection commands used with GitHub",
		Long: `Issues garbage collection commands used with GitHub

Examples:

wolfictl gc issues https://github.com/wolfi-dev/versions --match "version-stream:"
`,
		Args: cobra.RangeArgs(1, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !all && match == "" {
				return errors.New("you must either pass --all to close all issues or provide a match pattern with --match")
			}
			ts := oauth2.StaticTokenSource(
				&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
			)
			client := &http2.RLHTTPClient{
				Client: oauth2.NewClient(cmd.Context(), ts),

				// 1 request every (n) second(s) to avoid DOS'ing server. https://docs.github.com/en/rest/guides/best-practices-for-integrators?apiVersion=2022-11-28#dealing-with-secondary-rate-limits
				Ratelimiter: rate.NewLimiter(rate.Every(5*time.Second), 1),
			}

			return gcIssues(cmd.Context(), client, args[0], match)
		},
	}

	cmd.Flags().StringVar(&match, "match", "", "pattern to match issues against")
	cmd.Flags().BoolVar(&all, "all", false, "close all issues if set")

	return cmd
}

func gcIssues(ctx context.Context, ghclient *http2.RLHTTPClient, repo, match string) error {
	logger := log.New(log.Writer(), "wolfictl gh gc issues: ", log.LstdFlags|log.Lmsgprefix)

	gitURL, err := wgit.ParseGitURL(repo)
	if err != nil {
		return err
	}

	client := github.NewClient(ghclient.Client)
	gitOpts := gh.GitOptions{
		GithubClient: client,
		Logger:       logger,
	}

	// Get all issues
	issues, err := gitOpts.ListIssues(ctx, gitURL.Organisation, gitURL.Name, "open")
	if err != nil {
		return err
	}

	for _, issue := range issues {
		// Check if issue name starts with the match pattern
		if all || strings.HasPrefix(*issue.Title, match) {
			// Close the issue
			err := gitOpts.CloseIssue(ctx, gitURL.Organisation, gitURL.Name, "", *issue.Number)
			if err != nil {
				return err
			}
			logger.Printf("Deleted issue: %s\n", *issue.Title)
		}
	}
	return nil
}
