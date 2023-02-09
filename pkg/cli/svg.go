package cli

import (
	"fmt"
	"log"
	"os"

	"github.com/dominikbraun/graph"
	"github.com/goccy/go-graphviz"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/dag"
)

func cmdSVG() *cobra.Command {
	var dir, out string
	var showDependents bool
	svg := &cobra.Command{
		Use:   "svg",
		Short: "Generate a graphviz SVG",
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := dag.NewGraph(os.DirFS(dir), dir)
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
			return viz(*g, out)
		},
	}
	svg.Flags().StringVarP(&dir, "dir", "d", ".", "directory to search for melange configs")
	svg.Flags().StringVarP(&out, "out", "o", "dag.svg", "output file")
	svg.Flags().BoolVarP(&showDependents, "show-dependents", "D", false, "show packages that depend on these packages, instead of these packages' dependencies")
	return svg
}

func summarize(g dag.Graph) {
	log.Println("nodes:", g.Graph.Order())
	log.Println("edges:", g.Graph.Size())
}

func viz(g dag.Graph, out string) (err error) {
	v := graphviz.New()
	gr, err := v.Graph()
	if err != nil {
		log.Fatalf("graphviz: %v", err)
	}
	defer func() {
		if cerr := gr.Close(); err != nil {
			err = cerr
		}
		v.Close()
	}()

	nodes := g.Nodes()

	for _, node := range nodes {
		n, err := gr.CreateNode(node)
		if err != nil {
			return fmt.Errorf("graphviz: %w", err)
		}

		for _, dependency := range g.DependenciesOf(node) {
			depNode, err := gr.CreateNode(dependency)
			if err != nil {
				return fmt.Errorf("graphviz: %w", err)
			}

			if _, err := gr.CreateEdge("e", n, depNode); err != nil {
				return fmt.Errorf("graphviz: %w", err)
			}
		}
	}

	return v.RenderFilename(gr, graphviz.SVG, out)
}
