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
	var dir, pipelineDir, arch string
	var dryrun, buildtimeReposForRuntime bool
	text := &cobra.Command{
		Use:   "make",
		Short: "Run make for all targets in order",
		RunE: func(cmd *cobra.Command, args []string) error {
			arch := types.ParseArchitecture(arch).ToAPK()

			pkgs, err := dag.NewPackages(os.DirFS(dir), dir, pipelineDir)
			if err != nil {
				return err
			}
			g, err := dag.NewGraph(pkgs, dag.WithBuildtimeReposRuntime(buildtimeReposForRuntime))
			if err != nil {
				return err
			}

			filtered, err := g.Filter(dag.FilterLocal())
			if err != nil {
				return err
			}
			all, err := filtered.ReverseSorted()
			if err != nil {
				return err
			}

			for _, node := range all {
				name := node.Name()
				pkg, err := pkgs.PkgInfo(name)
				if err != nil {
					return err
				}
				if pkg == nil {
					continue
				}
				target := makeTarget(name, arch, pkg)
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
	text.Flags().StringVar(&pipelineDir, "pipeline-dir", "", "directory used to extend defined built-in pipelines")
	text.Flags().StringVarP(&arch, "arch", "a", "x86_64", "architecture to build for")
	text.Flags().BoolVar(&dryrun, "dryrun", false, "if true, only print `make` commands")
	text.Flags().BoolVar(&buildtimeReposForRuntime, "buildtime-repos-for-runtime", false, "use buildtime environment repositories to resolve runtime graph as well")
	return text
}
