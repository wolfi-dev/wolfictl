package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func cmdAdvisoryMove() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:     "move <old-package-name> <new-package-name>",
		Aliases: []string{"mv"},
		Short:   "Move a package's advisories into a new package.",
		Long: `Move a package's advisories into a new package.

This command will move most advisories for the given package into a new package. And rename the
package to the new package name. (i.e., from foo.advisories.yaml to foo-X.Y.advisories.yaml) If the
target file already exists, the command will try to merge the advisories. To ensure the advisories
are up-to-date, the command will start a scan for the new package.

This command is also useful to start version streaming for an existing package that has not been
version streamed before. Especially that requires manual intervention to move the advisories.

The command will move the latest event for each advisory, and will update the timestamp
of the event to now. The command will not copy events of type "detection", "fixed",
"analysis_not_planned", or "fix_not_planned".
`,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			have, want := args[0], args[1]

			have = strings.TrimSuffix(have, ".advisories.yaml")
			want = strings.TrimSuffix(want, ".advisories.yaml")

			advisoryFsys := rwos.DirFS(dir)
			advisoryCfgs, err := v2.NewIndex(ctx, advisoryFsys)
			if err != nil {
				return err
			}

			oldEntry, err := advisoryCfgs.Select().WhereName(have).First()
			if err != nil {
				return fmt.Errorf("unable to find advisory for package %q: %w", have, err)
			}
			oldDoc := oldEntry.Configuration()

			shouldMergeExistings := false
			newEntry, err := advisoryCfgs.Select().WhereName(want).First()
			if err == nil && len(newEntry.Configuration().Advisories) > 0 {
				shouldMergeExistings = true
			}

			out := *oldDoc
			out.Package.Name = want
			out.Advisories = nil

			for _, adv := range oldDoc.Advisories {
				if carried, ok := carryAdvisory(adv); ok {
					out.Advisories = append(out.Advisories, carried)
				}
			}

			havePath := have + ".advisories.yaml"
			wantPath := want + ".advisories.yaml"

			// If the new file already exists, merge the old advisories to it and re-create.
			if shouldMergeExistings {
				newDoc := newEntry.Configuration()

				updater := v2.NewAdvisoriesSectionUpdater(func(_ v2.Document) (v2.Advisories, error) {
					return mergeExistingAdvisories(out.Advisories, newDoc.Advisories), nil
				})

				if err := newEntry.Update(ctx, updater); err != nil {
					return fmt.Errorf("unable to update %q: %w", wantPath, err)
				}

				// Remove the existing file to re-create it since it's already existed.
				if err := advisoryCfgs.Remove(wantPath); err != nil {
					return fmt.Errorf("unable to remove old file %q: %w", wantPath, err)
				}
			}

			if err := advisoryCfgs.Remove(havePath); err != nil {
				return fmt.Errorf("unable to remove old file %q: %w", havePath, err)
			}

			return advisoryCfgs.Create(ctx, wantPath, out)
		},
	}
	cmd.PersistentFlags().StringVarP(&dir, "dir", "d", ".", "directory containing the advisories to copy")

	return cmd
}

// mergeExistingAdvisories merges the current advisories with the existing advisories.
func mergeExistingAdvisories(current, existing v2.Advisories) v2.Advisories {
	res := make(v2.Advisories, 0, len(current)+len(existing))

	// Add current advisories to the result and mark their IDs as seen
	res = append(res, current...)

	// Add existing advisories to the result if they are not already present
	for _, adv := range existing {
		if _, found := res.Get(adv.ID); !found {
			res = append(res, adv)
		}
	}

	return res
}
