package cli

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func cmdAdvisoryStream() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:     "stream <package-name> <version-streamed-package-name>",
		Aliases: []string{"stream"},
		Short:   "Start version streaming for a package by moving its advisories into a new package.",
		Long: `Start version streaming for a package by moving its advisories into a new package.

This command will move most advisories for the given package into a new package. And rename the
package to the new package name. (i.e., from foo.advisories.yaml to foo-X.Y.advisories.yaml) If the
target file already exists, the command will try to merge the advisories. To ensure the advisories
are up-to-date, the command will start a scan for the new package.

The command will move the latest event for each advisory, and will update the timestamp
of the event to now. The command will not copy events of type "detection", "fixed",
"analysis_not_planned", or "fix_not_planned".
`,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			old, new := args[0], args[1]

			old = strings.TrimSuffix(old, ".advisories.yaml")
			new = strings.TrimSuffix(new, ".advisories.yaml")

			if err := checkPackageHasVersionStreamSuffix(new); err != nil {
				return err
			}

			advisoryFsys := rwos.DirFS(dir)
			advisoryCfgs, err := v2.NewIndex(ctx, advisoryFsys)
			if err != nil {
				return err
			}

			oldEntry, err := advisoryCfgs.Select().WhereName(old).First()
			if err != nil {
				return fmt.Errorf("unable to find advisory for package %q: %w", old, err)
			}
			oldDoc := oldEntry.Configuration()

			shouldMergeExistings := false
			newEntry, err := advisoryCfgs.Select().WhereName(new).First()
			if err == nil && len(newEntry.Configuration().Advisories) > 0 {
				shouldMergeExistings = true
			}

			out := *oldDoc
			out.Package.Name = new
			out.Advisories = nil

			for _, adv := range oldDoc.Advisories {
				if carried, ok := carryAdvisory(adv); ok {
					out.Advisories = append(out.Advisories, carried)
				}
			}

			path := new + ".advisories.yaml"

			if shouldMergeExistings {
				newDoc := newEntry.Configuration()
				out.Advisories = mergeExistingAdvisories(out.Advisories, newDoc.Advisories)

				// Remove the existing file to re-create it.
				if err := os.Remove(path); err != nil {
					return fmt.Errorf("unable to remove existing file %q: %w", path, err)
				}
			}

			return advisoryCfgs.Create(ctx, path, out)
		},
	}
	cmd.PersistentFlags().StringVarP(&dir, "dir", "d", ".", "directory containing the advisories to copy")

	return cmd
}

// checkPackageHasVersionStreamSuffix ensures the package name has the "-X" or "-X.Y" suffix.
// X and Y are positive integers.
func checkPackageHasVersionStreamSuffix(pkg string) error {
	re := regexp.MustCompile(`-\d+(\.\d+)?$`)
	if re.MatchString(pkg) {
		return nil
	}
	return fmt.Errorf("new package name %q does not have the version stream suffix", pkg)
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
