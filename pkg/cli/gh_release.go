package cli

import (
	"errors"
	"log"
	"os"
	"time"

	"github.com/google/go-github/v58/github"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/gh"
	http2 "github.com/wolfi-dev/wolfictl/pkg/http"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
)

func Release() *cobra.Command {
	releaseOpts := gh.ReleaseOptions{
		Logger: log.New(log.Writer(), "wolfictl gh release: ", log.LstdFlags|log.Lmsgprefix),
	}

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
			ts := oauth2.StaticTokenSource(
				&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
			)

			ratelimit := &http2.RLHTTPClient{
				Client: oauth2.NewClient(cmd.Context(), ts),

				// 1 request every (n) second(s) to avoid DOS'ing server. https://docs.github.com/en/rest/guides/best-practices-for-integrators?apiVersion=2022-11-28#dealing-with-secondary-rate-limits
				Ratelimiter: rate.NewLimiter(rate.Every(3*time.Second), 1),
			}

			releaseOpts.GithubClient = github.NewClient(ratelimit.Client)

			if !releaseOpts.BumpMajor &&
				!releaseOpts.BumpMinor &&
				!releaseOpts.BumpPatch &&
				releaseOpts.BumpPrereleaseWithPrefix == "" {
				return errors.New("missing flag to bump release version")
			}

			return releaseOpts.Release(cmd.Context())
		},
	}

	cmd.Flags().BoolVar(&releaseOpts.BumpMajor, "bump-major", false, "bumps the major release version")
	cmd.Flags().BoolVar(&releaseOpts.BumpMinor, "bump-minor", false, "bumps the minor release version")
	cmd.Flags().BoolVar(&releaseOpts.BumpPatch, "bump-patch", false, "bumps the patch release version")
	cmd.Flags().StringVar(&releaseOpts.BumpPrereleaseWithPrefix, "bump-prerelease-with-prefix", "", "bumps the prerelease version using the supplied prefix, if no existing prerelease exists the patch version is also bumped to align with semantic versioning")
	cmd.Flags().StringVar(&releaseOpts.Dir, "dir", ".", "directory containing the cloned github repository to release")

	return cmd
}
