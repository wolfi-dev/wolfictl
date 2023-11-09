package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
)

func cmdAdvisoryDiff() *cobra.Command {
	p := &diffParams{}
	cmd := &cobra.Command{
		Use:           "diff",
		Short:         "See the advisory data differences introduced by your local changes",
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var advisoriesGitUpstreamRemoteURL string
			// TODO: how will this get set if we don't auto-detect?

			advisoriesRepoDir := resolveAdvisoriesDirInput(p.advisoriesRepoDir)
			if advisoriesRepoDir == "" {
				if p.doNotDetectDistro {
					return fmt.Errorf("no advisories repo dir specified")
				}

				d, err := distro.Detect()
				if err != nil {
					return fmt.Errorf("no advisories repo dir specified, and distro auto-detection failed: %w", err)
				}

				// Get an HTTPS URL for the upstream Git remote
				for _, u := range d.Absolute.AdvisoriesRemoteURLs {
					if strings.HasPrefix(u, "https://") {
						advisoriesGitUpstreamRemoteURL = u
						break
					}
				}

				advisoriesRepoDir = d.Local.AdvisoriesRepoDir
				_, _ = fmt.Fprint(os.Stderr, renderDetectedDistro(d))
			}

			currentAdvisoriesFsys := rwos.DirFS(advisoriesRepoDir)
			currentAdvisoriesIndex, err := v2.NewIndex(currentAdvisoriesFsys)
			if err != nil {
				return err
			}

			dir, err := os.MkdirTemp("", "wolfictl-advisory-diff-*")
			if err != nil {
				return fmt.Errorf("unable to create temp directory for advisories clone: %w", err)
			}
			defer os.RemoveAll(dir)

			auth := &http.BasicAuth{
				Username: "username", // We don't need the user's actual GH username! (but it can't be empty)
				Password: os.Getenv("GITHUB_TOKEN"),
			}

			_, err = git.PlainClone(dir, false, &git.CloneOptions{
				Auth:  auth,
				Depth: 1,
				URL:   advisoriesGitUpstreamRemoteURL,
			})
			if err != nil {
				return fmt.Errorf("unable to clone advisories repo to temp directory: %w", err)
			}

			baseAdvisoriesFsys := rwos.DirFS(dir)
			baseAdvisoriesIndex, err := v2.NewIndex(baseAdvisoriesFsys)
			if err != nil {
				return err
			}

			// Diff!

			diff := advisory.IndexDiff(baseAdvisoriesIndex, currentAdvisoriesIndex)
			fmt.Println(renderDiff(diff))

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type diffParams struct {
	doNotDetectDistro bool
	advisoriesRepoDir string
}

func (p *diffParams) addFlagsTo(cmd *cobra.Command) {
	addNoDistroDetectionFlag(&p.doNotDetectDistro, cmd)
	addAdvisoriesDirFlag(&p.advisoriesRepoDir, cmd)
}

func renderDiff(result advisory.IndexDiffResult) string {
	if result.IsZero() {
		return "(no differences)"
	}

	var sb strings.Builder

	fmt.Fprintf(&sb, "( %s / %s / %s )\n\n",
		styleRemoved.Render("- removed"),
		styleModified.Render("~ modified"),
		styleAdded.Render("+ added"),
	)

	for _, doc := range result.Removed {
		fprintRemovedf(&sb, "- document %q", doc.Name())
		for _, adv := range doc.Advisories {
			fprintRemovedf(&sb, "  - advisory %q", adv.ID)
		}
	}
	for _, doc := range result.Added {
		fprintAddedf(&sb, "+ document %q", doc.Name())
		for _, adv := range doc.Advisories {
			fprintAddedf(&sb, "  + advisory %q", adv.ID)
		}
	}
	for _, docDiff := range result.Modified {
		fprintModifiedf(&sb, "~ document %q", docDiff.Name)
		for _, adv := range docDiff.Removed {
			fprintRemovedf(&sb, "  - advisory %q", adv.ID)
		}
		for _, adv := range docDiff.Added {
			fprintAddedf(&sb, "  + advisory %q", adv.ID)
		}
		for i := range docDiff.Modified {
			advDiff := docDiff.Modified[i]
			fprintModifiedf(&sb, "  ~ advisory %q", advDiff.ID)

			if nonEventDiff := cmp.Diff(
				advDiff.Removed,
				advDiff.Added,
				cmpopts.IgnoreFields(v2.Advisory{}, "Events"),
			); nonEventDiff != "" {
				fmt.Fprint(&sb, renderCmpDiffOutput(nonEventDiff))
			}

			for _, event := range advDiff.RemovedEvents {
				fprintRemovedf(&sb, "    - event %q @ %s", event.Type, event.Timestamp)
			}
			for _, event := range advDiff.AddedEvents {
				fprintAddedf(&sb, "    + event %q @ %s", event.Type, event.Timestamp)
			}
		}
	}

	return sb.String()
}

// renderCmpDiffOutput renders the output of a cmp.Diff call, by filtering out
// any unchanged lines, and by coloring lines whose first non-space character is
// prefixed with a + or -.
func renderCmpDiffOutput(diff string) string {
	var sb strings.Builder

	for _, line := range strings.Split(diff, "\n") {
		if line == "" {
			continue
		}

		if line[0] == ' ' {
			continue
		}

		if line[0] == '+' {
			fmt.Fprintf(&sb, "    %s\n", styleAdded.Render(line))
			continue
		}

		if line[0] == '-' {
			fmt.Fprintf(&sb, "    %s\n", styleRemoved.Render(line))
			continue
		}
	}

	return sb.String()
}

func fprintAddedf(w io.Writer, format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	fmt.Fprint(w, styleAdded.Render(s)+"\n")
}

func fprintRemovedf(w io.Writer, format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	fmt.Fprint(w, styleRemoved.Render(s)+"\n")
}

func fprintModifiedf(w io.Writer, format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	fmt.Fprint(w, styleModified.Render(s)+"\n")
}

var (
	styleRemoved  = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff4d4d"))
	styleAdded    = lipgloss.NewStyle().Foreground(lipgloss.Color("#04d404"))
	styleModified = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffdb12"))
)
