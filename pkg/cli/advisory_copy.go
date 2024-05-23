package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
)

func cmdAdvisoryCopy() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:     "copy <source-package-name> <destination-package-name>",
		Aliases: []string{"cp"},
		Short:   "Copy a package's advisories into a new package.",
		Long: `Copy a package's advisories into a new package.

This command will copy most advisories for the given package into a new package.

The command will copy the latest event for each advisory, and will update the timestamp
of the event to now. The command will not copy events of type "detection", "fixed",
"analysis_not_planned", or "fix_not_planned".
`,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			have, want := args[0], args[1]

			have = strings.TrimSuffix(have, ".advisories.yaml")

			advisoryFsys := rwos.DirFS(dir)
			advisoryCfgs, err := v2.NewIndex(ctx, advisoryFsys)
			if err != nil {
				return err
			}

			hadv, err := advisoryCfgs.Select().WhereName(have).First()
			if err != nil {
				return fmt.Errorf("unable to find advisory for package %q: %w", have, err)
			}
			hdoc := hadv.Configuration()

			out := *hdoc
			out.Package.Name = want
			out.Advisories = nil

			for _, adv := range hdoc.Advisories {
				evts := make([]v2.Event, 0, len(adv.Events))

				for _, evt := range adv.Events {
					switch evt.Type {
					case v2.EventTypeDetection, v2.EventTypeFixed, v2.EventTypeAnalysisNotPlanned, v2.EventTypeFixNotPlanned:
						// Don't carry these over.
						continue

					case v2.EventTypePendingUpstreamFix, v2.EventTypeFalsePositiveDetermination, v2.EventTypeTruePositiveDetermination:
						// Carry these over as-is.
						evts = append(evts, evt)

					default:
						// A new type was added and we don't know how to handle it. Default to not carrying it over.
					}
				}

				if len(evts) == 0 {
					// No events to carry over.
					continue
				}

				// Sort events by timestamp and only take the latest event.
				sort.Slice(evts, func(i, j int) bool {
					return evts[i].Timestamp.Before(evts[j].Timestamp)
				})
				evts = []v2.Event{evts[len(evts)-1]}

				// Update the timestamp to now.
				evts[0].Timestamp = v2.Now()

				adv.Events = evts
				out.Advisories = append(out.Advisories, adv)
			}

			return advisoryCfgs.Create(ctx, want+".advisories.yaml", out)
		},
	}
	cmd.PersistentFlags().StringVarP(&dir, "dir", "d", ".", "directory containing the advisories to copy")

	return cmd
}
