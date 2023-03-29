package cli

import (
	"fmt"
	"io"
	"log"
	"os"

	"chainguard.dev/apko/pkg/build/types"
	"github.com/dominikbraun/graph"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/dag"
)

func cmdText() *cobra.Command {
	var dir, arch, t string
	var showDependents bool
	text := &cobra.Command{
		Use:   "text",
		Short: "Print a sorted list of downstream dependent packages",
		RunE: func(cmd *cobra.Command, args []string) error {
			arch := types.ParseArchitecture(arch).ToAPK()

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

			return text(*g, arch, textType(t), os.Stdout)
		},
	}
	text.Flags().StringVarP(&dir, "dir", "d", ".", "directory to search for melange configs")
	text.Flags().StringVarP(&arch, "arch", "a", "x86_64", "architecture to build for")
	text.Flags().BoolVarP(&showDependents, "show-dependents", "D", false, "show packages that depend on these packages, instead of these packages' dependencies")
	text.Flags().StringVarP(&t, "type", "t", string(typeTarget), fmt.Sprintf("What type of text to emit; values can be one of: %v", textTypes))
	return text
}

type textType string

const (
	typeTarget                textType = "target"
	typeMakefileLine          textType = "makefile"
	typePackageName           textType = "name"
	typePackageVersion        textType = "version"
	typePackageNameAndVersion textType = "name-version"
)

var textTypes = []textType{
	typeTarget,
	typeMakefileLine,
	typePackageName,
	typePackageVersion,
	typePackageNameAndVersion,
}

func reverse(ss []string) {
	last := len(ss) - 1
	for i := 0; i < len(ss)/2; i++ {
		ss[i], ss[last-i] = ss[last-i], ss[i]
	}
}

func text(g dag.Graph, arch string, t textType, w io.Writer) error {
	all, err := g.Sorted()
	if err != nil {
		return err
	}
	reverse(all)

	for _, node := range all {
		switch t {
		case typeTarget:
			target, err := g.MakeTarget(node, arch)
			if err != nil {
				return err
			}
			if target != "" {
				fmt.Fprintf(w, "%s\n", target)
			}
		case typeMakefileLine:
			entry, err := g.MakefileEntry(node)
			if err != nil {
				return err
			}
			if entry != "" {
				fmt.Fprintf(w, "%s\n", entry)
			}
		case typePackageName:
			pkg, err := g.PkgInfo(node, arch)
			if err != nil {
				return err
			}
			if pkg != nil && pkg.Name != "" {
				fmt.Fprintf(w, "%s\n", pkg.Name)
			}
		case typePackageVersion:
			pkg, err := g.PkgInfo(node, arch)
			if err != nil {
				return err
			}
			if pkg != nil && pkg.Version != "" {
				fmt.Fprintf(w, "%s\n", pkg.Version)
			}
		case typePackageNameAndVersion:
			pkg, err := g.PkgInfo(node, arch)
			if err != nil {
				return err
			}
			if pkg != nil && pkg.Name != "" && pkg.Version != "" {
				fmt.Fprintf(w, "%s-%s\n", pkg.Name, pkg.Version)
			}
		default:
			return fmt.Errorf("invalid type: %s", t)
		}
	}

	return nil
}
