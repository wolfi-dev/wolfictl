package cli

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	ghauth "github.com/cli/go-gh/v2/pkg/auth"
	"github.com/google/go-github/v55/github"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"

	"github.com/wolfi-dev/wolfictl/pkg/gh"
	wgit "github.com/wolfi-dev/wolfictl/pkg/git"
	http2 "github.com/wolfi-dev/wolfictl/pkg/http"
)

var match string
var all bool

func Branch() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "branch",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		Short:             "Branch garbage collection commands used with GitHub",
		Long: `Branch garbage collection commands used with GitHub

Examples:

wolfictl gh gc branch https://github.com/wolfi-dev/os --match "wolfictl-"
`,
		Args: cobra.RangeArgs(1, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !all && match == "" {
				return errors.New("you must either pass --all to close all branches or provide a match pattern with --match")
			}
			client := &http2.RLHTTPClient{
				Client: oauth2.NewClient(context.Background(), ghTokenSource{}),

				// 1 request every (n) second(s) to avoid DOS'ing server. https://docs.github.com/en/rest/guides/best-practices-for-integrators?apiVersion=2022-11-28#dealing-with-secondary-rate-limits
				Ratelimiter: rate.NewLimiter(rate.Every(5*time.Second), 1),
			}

			return gcBranches(client, args[0], match)
		},
	}

	cmd.Flags().StringVar(&match, "match", "", "pattern to match branches against")
	cmd.Flags().BoolVar(&all, "all", false, "close all branches if set")

	return cmd
}

type ghTokenSource struct{}

func (ghTokenSource) Token() (*oauth2.Token, error) {
	if tok, _ := ghauth.TokenForHost("github.com"); tok != "" {
		return &oauth2.Token{AccessToken: tok}, nil
	}
	return nil, errors.New("could not find github token")
}

func gcBranches(ghclient *http2.RLHTTPClient, repo, match string) error {
	logger := log.New(log.Writer(), "wolfictl gh gc branch: ", log.LstdFlags|log.Lmsgprefix)
	ctx := context.Background()

	gitURL, err := wgit.ParseGitURL(repo)
	if err != nil {
		return err
	}

	client := github.NewClient(ghclient.Client)
	gitOpts := gh.GitOptions{
		GithubClient: client,
		Logger:       logger,
	}

	// Get all branches
	branches, err := gitOpts.ListBranches(ctx, gitURL.Organisation, gitURL.Name)
	if err != nil {
		return err
	}

	// Get all open pull requests
	pulls, err := gitOpts.ListPullRequests(ctx, gitURL.Organisation, gitURL.Name, "open")
	if err != nil {
		return err
	}

	// Create a map of existing pull requests for easy lookup
	existingPRs := make(map[string]bool)
	for _, pull := range pulls {
		existingPRs[*pull.Head.Ref] = true
	}

	for _, branch := range branches {
		// Check if branch name starts with the match pattern
		if all || strings.HasPrefix(*branch.Name, match) {
			// Check if there are any open pull requests for this branch
			if _, ok := existingPRs[*branch.Name]; ok {
				log.Printf("Skipping branch %s, there are open pull requests for it\n", *branch.Name)
				continue
			}

			// Delete the branch
			_, err := client.Git.DeleteRef(ctx, gitURL.Organisation, gitURL.Name, "refs/heads/"+*branch.Name)
			if err != nil {
				return err
			}
			log.Printf("Deleted branch: %s\n", *branch.Name)
		}
	}
	return nil
}
