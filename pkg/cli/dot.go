package cli

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/dominikbraun/graph"
	"github.com/spf13/cobra"
	"github.com/tmc/dot"
	"github.com/wolfi-dev/wolfictl/pkg/dag"
)

func cmdSVG() *cobra.Command {
	var dir, pipelineDir string
	var showDependents, buildtimeReposForRuntime bool
	d := &cobra.Command{
		Use:   "dot",
		Short: "Generate graphviz .dot output",
		Long: `
Generate .dot output and pipe it to dot to generate an SVG

  wolfictl dot | dot -Tsvg > graph.svg

Generate .dot output and pipe it to dot to generate a PNG

  wolfictl dot | dot -Tpng > graph.png
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if pipelineDir == "" {
				pipelineDir = filepath.Join(dir, "pipelines")
			}

			pkgs, err := dag.NewPackages(os.DirFS(dir), dir, pipelineDir)
			if err != nil {
				return err
			}
			g, err := dag.NewGraph(pkgs, dag.WithBuildtimeReposRuntime(buildtimeReposForRuntime))
			if err != nil {
				return err
			}

			if len(args) == 0 {
				if showDependents {
					log.Print("warning: the 'show dependents' option has no effect without specifying one or more package names")
				}
			} else {
				// ensure all packages exist in the graph
				for _, arg := range args {
					if _, err := g.Graph.Vertex(arg); err == graph.ErrVertexNotFound {
						return fmt.Errorf("package %q not found in graph", arg)
					}
				}

				// determine if we're examining dependencies or dependents
				var subgraph *dag.Graph
				if showDependents {
					leaves := args
					subgraph, err = g.SubgraphWithLeaves(leaves)
					if err != nil {
						return err
					}
				} else {
					roots := args
					subgraph, err = g.SubgraphWithRoots(roots)
					if err != nil {
						return err
					}
				}

				g = subgraph
			}

			summarize(*g)
			return viz(*g)
		},
	}
	d.Flags().StringVarP(&dir, "dir", "d", ".", "directory to search for melange configs")
	d.Flags().StringVar(&pipelineDir, "pipeline-dir", "", "directory used to extend defined built-in pipelines")
	d.Flags().BoolVarP(&showDependents, "show-dependents", "D", false, "show packages that depend on these packages, instead of these packages' dependencies")
	d.Flags().BoolVar(&buildtimeReposForRuntime, "buildtime-repos-for-runtime", false, "use buildtime environment repositories to resolve runtime graph as well")
	return d
}

func summarize(g dag.Graph) {
	order, err := g.Graph.Order()
	if err != nil {
		log.Printf("unable to get number of nodes in graph: %s", err)
		return
	}
	log.Println("nodes:", order)

	size, err := g.Graph.Size()
	if err != nil {
		log.Printf("unable to get number of edges in graph: %s", err)
		return
	}
	log.Println("edges:", size)
}

func viz(g dag.Graph) error {
	out := dot.NewGraph("images")
	out.SetType(dot.DIGRAPH)

	nodes := g.Packages()

	adjacencyMap, err := g.Graph.AdjacencyMap()
	if err != nil {
		return err
	}

	for _, node := range nodes {
		n := dot.NewNode(node)
		out.AddNode(n)

		if deps, ok := adjacencyMap[node]; ok {
			dependencies := make([]string, 0, len(deps))
			for dep := range deps {
				dependencies = append(dependencies, dep)
			}
			sort.Strings(dependencies)

			for _, dependency := range dependencies {
				d := dot.NewNode(dependency)
				out.AddNode(d)
				out.AddEdge(dot.NewEdge(n, d))
			}
		}
	}

	fmt.Println(out.String())
	return nil
}
