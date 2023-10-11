package cli

import (
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
)

func cmdAdvisoryAliasDiscover() *cobra.Command {
	p := &aliasDiscoverParams{}
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "discover new aliases for vulnerabilities in the advisory data",
		Long: `Discover new aliases for vulnerabilities in the advisory data.

This command reads the advisory data and searches for new aliases for the ID 
and aliases of each advisory. For any new aliases found, the advisory data is 
updated to include the new alias.

This command uses the GitHub API to query GHSA information. Note that GitHub 
enforces a stricter rate limit against unauthenticated API calls. You can 
authenticate this command's API calls by setting the environment variable 
GITHUB_TOKEN to a personal access token. When performing alias discovery across 
the entire data set, authenticating these API calls is highly recommended.

You may pass one or more instances of -p/--package to have the command operate 
on only one or more packages, rather than on the entire advisory data set.

Where possible, this command also normalizes advisories to use the relevant CVE 
ID as the advisory ID instead of an ID from another vulnerability namespace. 
This means, for example, that a non-CVE ID (e.g. a GHSA ID) that was previously 
the advisory ID will be moved to the advisory's aliases if a canonical CVE ID 
is discovered, since the CVE ID will become the advisory's new ID.

In cases where an advisory's ID is updated, the advisory document will be 
re-sorted by advisory ID so that the resulting advisories are still sorted 
correctly. Also, if updating an advisory ID results in an advisory document 
having two or more advisories with the same ID, the command errors out rather 
than attempting any kind of merge of the separate advisories.
`,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			advisoriesRepoDir := resolveAdvisoriesDirInput(p.advisoriesRepoDir)
			if advisoriesRepoDir == "" {
				if p.doNotDetectDistro {
					return fmt.Errorf("no advisories repo dir specified")
				}

				d, err := distro.Detect()
				if err != nil {
					return fmt.Errorf("no advisories repo dir specified, and distro auto-detection failed: %w", err)
				}

				advisoriesRepoDir = d.AdvisoriesRepoDir
				_, _ = fmt.Fprint(os.Stderr, renderDetectedDistro(d))
			}

			advisoriesFsys := rwos.DirFS(advisoriesRepoDir)
			advisoryDocs, err := v2.NewIndex(advisoriesFsys)
			if err != nil {
				return err
			}

			selectedPackageSet := make(map[string]struct{})
			for _, pkg := range p.packages {
				selectedPackageSet[pkg] = struct{}{}
			}

			opts := advisory.DiscoverAliasesOptions{
				AdvisoryDocs:     advisoryDocs,
				AliasFinder:      advisory.NewHTTPAliasFinder(http.DefaultClient),
				SelectedPackages: selectedPackageSet,
			}

			return advisory.DiscoverAliases(cmd.Context(), opts)
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type aliasDiscoverParams struct {
	advisoriesRepoDir string
	doNotDetectDistro bool

	packages []string
}

func (p *aliasDiscoverParams) addFlagsTo(cmd *cobra.Command) {
	addAdvisoriesDirFlag(&p.advisoriesRepoDir, cmd)
	addNoDistroDetectionFlag(&p.doNotDetectDistro, cmd)

	cmd.Flags().StringSliceVarP(&p.packages, "package", "p", nil, "packages to operate on")
}
