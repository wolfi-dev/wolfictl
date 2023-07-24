package cli

import (
	"fmt"
	"io"
	"log"
	"os"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/build"
	"github.com/dominikbraun/graph"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/dag"
)

func cmdText() *cobra.Command {
	var dir, pipelineDir, arch, t string
	var showDependents bool
	text := &cobra.Command{
		Use:   "text",
		Short: "Print a sorted list of downstream dependent packages",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			arch := types.ParseArchitecture(arch).ToAPK()

			pkgs, err := dag.NewPackages(ctx, os.DirFS(dir), dir, pipelineDir)
			if err != nil {
				return err
			}
			g, err := dag.NewGraph(ctx, pkgs)
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
					subgraph, err = g.SubgraphWithRoots(ctx, roots)
					if err != nil {
						return err
					}
				}

				g = subgraph
			}

			return text(*g, pkgs, arch, textType(t), os.Stdout)
		},
	}
	text.Flags().StringVarP(&dir, "dir", "d", ".", "directory to search for melange configs")
	text.Flags().StringVar(&pipelineDir, "pipeline-dir", "", "directory used to extend defined built-in pipelines")
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

func text(g dag.Graph, pkgs *dag.Packages, arch string, t textType, w io.Writer) error {
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
		if pkg == nil || pkg.Name == "" {
			continue
		}
		switch t {
		case typeTarget:
			fmt.Fprintf(w, "%s\n", makeTarget(name, arch, pkg))
		case typeMakefileLine:
			fmt.Fprintf(w, "%s\n", makefileEntry(name, pkg))
		case typePackageName:
			fmt.Fprintf(w, "%s\n", pkg.Name)
		case typePackageVersion:
			fmt.Fprintf(w, "%s\n", pkg.Version)
		case typePackageNameAndVersion:
			fmt.Fprintf(w, "%s-%s-r%d\n", pkg.Name, pkg.Version, pkg.Epoch)
		default:
			return fmt.Errorf("invalid type: %s", t)
		}
	}

	return nil
}

func makefileEntry(pkgName string, p *build.Package) string {
	return fmt.Sprintf("$(eval $(call build-package,%s,%s-%d))", pkgName, p.Version, p.Epoch)
}

func makeTarget(pkgName, arch string, p *build.Package) string {
	// note: using pkgName here because it may be a subpackage, not the main package declared within the config (i.e. `p.Name`)
	return fmt.Sprintf("make packages/%s/%s-%s-r%d.apk", arch, pkgName, p.Version, p.Epoch)
}
