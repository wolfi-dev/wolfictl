package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	v2 "github.com/chainguard-dev/advisory-schema/pkg/advisory/v2"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	adv2 "github.com/wolfi-dev/wolfictl/pkg/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
	wgit "github.com/wolfi-dev/wolfictl/pkg/git"
)

func cmdAdvisoryDiff() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "diff",
		Short:         "See the advisory data differences introduced by your local changes",
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, err := distro.Detect()
			if err != nil {
				return fmt.Errorf("distro auto-detection failed: %w", err)
			}

			fmt.Fprint(os.Stderr, renderDetectedDistro(d))

			advisoriesRepoURL, err := getAdvisoriesHTTPSRemoteURL(d)
			if err != nil {
				return err
			}

			// Clone the upstream repo to a temp directory
			useAuth := d.Absolute.Name != "Wolfi"
			baseRef := d.Local.AdvisoriesRepo.ForkPoint
			cloneDir, err := wgit.TempClone(advisoriesRepoURL, baseRef, useAuth)
			defer os.RemoveAll(cloneDir)
			if err != nil {
				return fmt.Errorf("unable to produce a base repo state for comparison: %w", err)
			}

			baseAdvisoriesFsys := rwos.DirFS(cloneDir)
			baseAdvisoriesIndex, err := adv2.NewIndex(cmd.Context(), baseAdvisoriesFsys)
			if err != nil {
				return err
			}

			currentAdvisoriesIndex, err := adv2.NewIndex(cmd.Context(), rwos.DirFS(d.Local.AdvisoriesRepo.Dir))
			if err != nil {
				return err
			}

			// Diff!

			diff := advisory.IndexDiff(baseAdvisoriesIndex, currentAdvisoriesIndex)
			fmt.Println(renderDiff(diff))

			return nil
		},
	}

	return cmd
}

func getAdvisoriesHTTPSRemoteURL(d distro.Distro) (string, error) {
	for _, u := range d.Absolute.AdvisoriesRemoteURLs() {
		if strings.HasPrefix(u, "https://") {
			return u, nil
		}
	}

	return "", fmt.Errorf("no HTTPS remote URL found for advisories repo for distro %q", d.Absolute.Name)
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

		if strings.Contains(line, "ignored field") {
			// We're only ignoring the Events field, because we want to control the rendered
			// diff of Events ourselves. Seeing the "ignored field" warning from cmp.Diff is
			// sort of confusing.
			continue
		}

		switch line[0] {
		case ' ':
			fmt.Fprintf(&sb, "    %s\n", line)

		case '+':
			fmt.Fprintf(&sb, "    %s\n", styleAdded.Render(line))

		case '-':
			fmt.Fprintf(&sb, "    %s\n", styleRemoved.Render(line))
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
