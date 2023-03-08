package cli

import (
	"fmt"
	"os"
	"os/exec"

	"chainguard.dev/apko/pkg/build/types"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/dag"
)

func cmdMake() *cobra.Command {
	var dir, arch string
	var dryrun bool
	text := &cobra.Command{
		Use:   "make",
		Short: "Run make for all targets in order",
		RunE: func(cmd *cobra.Command, args []string) error {
			arch := types.ParseArchitecture(arch).ToAPK()

			g, err := dag.NewGraph(os.DirFS(dir), dir)
			if err != nil {
				return err
			}

			all, err := g.Sorted()
			if err != nil {
				return err
			}
			reverse(all)

			for _, node := range all {
				target, err := g.MakeTarget(node, arch)
				if err != nil {
					return err
				}
				if target == "" { // ignore subpackages
					continue
				}
				if dryrun {
					fmt.Println(target)
				} else {
					if err := exec.Command("sh", "-c", target).Run(); err != nil {
						return err
					}
				}
			}
			return nil
		},
	}
	text.Flags().StringVarP(&dir, "dir", "d", ".", "directory to search for melange configs")
	text.Flags().StringVarP(&arch, "arch", "a", "x86_64", "architecture to build for")
	text.Flags().BoolVar(&dryrun, "dryrun", false, "if true, only print `make` commands")
	return text
}
