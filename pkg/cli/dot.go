package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"
	"github.com/tmc/dot"
	"github.com/wolfi-dev/wolfictl/pkg/dag"
)

func cmdSVG() *cobra.Command {
	var dir, pipelineDir string
	var showDependents, buildtimeReposForRuntime bool
	var extraKeys, extraRepos []string
	d := &cobra.Command{
		Use:   "dot",
		Short: "Generate graphviz .dot output",
		Args:  cobra.MinimumNArgs(1),
		Long: `
Generate .dot output and pipe it to dot to generate an SVG

  wolfictl dot zlib | dot -Tsvg > graph.svg

Generate .dot output and pipe it to dot to generate a PNG

  wolfictl dot zlib | dot -Tpng > graph.png
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if pipelineDir == "" {
				pipelineDir = filepath.Join(dir, "pipelines")
			}

			pkgs, err := dag.NewPackages(os.DirFS(dir), dir, pipelineDir)
			if err != nil {
				return fmt.Errorf("NewPackages: %w", err)
			}

			g, err := dag.NewGraph(pkgs,
				dag.WithBuildtimeReposRuntime(buildtimeReposForRuntime),
				dag.WithKeys(extraKeys...),
				dag.WithRepos(extraRepos...),
			)
			if err != nil {
				return fmt.Errorf("building graph: %w", err)
			}

			out := dot.NewGraph("images")
			out.SetType(dot.DIGRAPH)

			amap, err := g.Graph.AdjacencyMap()
			if err != nil {
				return err
			}

			pmap, err := g.Graph.PredecessorMap()
			if err != nil {
				return err
			}

			for _, node := range args {
				n := dot.NewNode(node)
				out.AddNode(n)

				byName, err := g.NodesByName(node)
				if err != nil {
					return err
				}

				if len(byName) == 0 {
					return fmt.Errorf("could not find node %q", node)
				}

				for _, name := range byName {
					dependencies, ok := amap[dag.PackageHash(name)]
					if !ok {
						continue
					}

					deps := make([]string, 0, len(dependencies))
					for dep := range dependencies {
						deps = append(deps, dep)
					}
					sort.Strings(deps)

					for _, dep := range deps {
						d := dot.NewNode(dep)
						out.AddNode(d)
						out.AddEdge(dot.NewEdge(n, d))
					}

					if !showDependents {
						continue
					}

					predecessors, ok := pmap[dag.PackageHash(name)]
					if !ok {
						continue
					}

					preds := make([]string, 0, len(predecessors))
					for pred := range predecessors {
						preds = append(preds, pred)
					}
					sort.Strings(preds)

					for _, pred := range preds {
						d := dot.NewNode(pred)
						out.AddNode(d)
						out.AddEdge(dot.NewEdge(d, n))
					}
				}
			}
			fmt.Println(out.String())
			return nil
		},
	}
	d.Flags().StringVarP(&dir, "dir", "d", ".", "directory to search for melange configs")
	d.Flags().StringVar(&pipelineDir, "pipeline-dir", "", "directory used to extend defined built-in pipelines")
	d.Flags().BoolVarP(&showDependents, "show-dependents", "D", false, "show packages that depend on these packages, instead of these packages' dependencies")
	d.Flags().BoolVar(&buildtimeReposForRuntime, "buildtime-repos-for-runtime", false, "use buildtime environment repositories to resolve runtime graph as well")
	d.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the build environment keyring")
	d.Flags().StringSliceVarP(&extraRepos, "repository-append", "r", []string{}, "path to extra repositories to include in the build environment")
	return d
}
