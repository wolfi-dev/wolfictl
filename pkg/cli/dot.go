package cli

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tmc/dot"
	"github.com/wolfi-dev/wolfictl/pkg/dag"
	"golang.org/x/sync/errgroup"

	"github.com/skratchdot/open-golang/open"
)

func cmdSVG() *cobra.Command { //nolint:gocyclo
	var dir, pipelineDir string
	var showDependents, recursive, span, buildtimeReposForRuntime, web bool
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

Open browser to explore crane

  wolfictl dot --web crane

Open browser to explore crane's deps recursively, only showing a minimum subgraph

  wolfictl dot --web -R -S crane
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

			amap, err := g.Graph.AdjacencyMap()
			if err != nil {
				return err
			}

			pmap, err := g.Graph.PredecessorMap()
			if err != nil {
				return err
			}

			render := func(args []string) (*dot.Graph, error) {
				todo := []string{}
				queued := map[string]struct{}{}

				out := dot.NewGraph("images")
				if err := out.Set("rankdir", "LR"); err != nil {
					return nil, err
				}
				out.SetType(dot.DIGRAPH)

				renderNode := func(node string) error {
					var byName []dag.Package
					config := pkgs.ConfigByKey(node)
					if config != nil {
						byName = append(byName, config)
					} else {
						byName, err = g.NodesByName(node)
						if err != nil {
							return err
						}

						if len(byName) == 0 {
							return fmt.Errorf("could not find node %q", node)
						}
					}

					for _, name := range byName {
						h := dag.PackageHash(name)

						pkgver, source := split(h)
						n := dot.NewNode(pkgver)
						if err := n.Set("tooltip", source); err != nil {
							return err
						}
						if pkgs.ConfigByKey(pkgver) != nil {
							if web {
								if err := n.Set("URL", link(args, pkgver)); err != nil {
									return err
								}
							}
						} else {
							if err := n.Set("color", "red"); err != nil {
								return err
							}
						}
						out.AddNode(n)

						dependencies, ok := amap[h]
						if !ok {
							continue
						}

						deps := make([]string, 0, len(dependencies))
						for dep := range dependencies {
							deps = append(deps, dep)
						}
						sort.Strings(deps)

						for _, dep := range deps {
							if recursive || span {
								if _, ok := queued[dep]; ok {
									if span {
										continue
									}
								} else {
									todo = append(todo, dep)
									queued[dep] = struct{}{}
								}
							}

							pkgver, source := split(dep)
							d := dot.NewNode(pkgver)
							if err := d.Set("tooltip", source); err != nil {
								return err
							}
							if pkgs.ConfigByKey(pkgver) != nil {
								if web {
									if err := d.Set("URL", link(args, pkgver)); err != nil {
										return err
									}
								}
							} else {
								if err := d.Set("color", "red"); err != nil {
									return err
								}
							}
							out.AddNode(d)
							out.AddEdge(dot.NewEdge(n, d))
						}

						if !showDependents {
							continue
						}

						predecessors, ok := pmap[h]
						if !ok {
							continue
						}

						preds := make([]string, 0, len(predecessors))
						for pred := range predecessors {
							preds = append(preds, pred)
						}
						sort.Strings(preds)

						for _, pred := range preds {
							pkgver, source := split(pred)
							d := dot.NewNode(pkgver)
							if err := d.Set("tooltip", source); err != nil {
								return err
							}
							if pkgs.ConfigByKey(pkgver) != nil {
								if web {
									if err := d.Set("URL", link(args, pkgver)); err != nil {
										return err
									}
								}
							}
							out.AddNode(d)
							out.AddEdge(dot.NewEdge(d, n))
						}
					}

					return nil
				}

				for _, node := range args {
					if err := renderNode(node); err != nil {
						return nil, err
					}
				}

				if recursive {
					var node string
					for len(todo) != 0 {
						node, todo = pop(todo)

						pkgver, _ := split(node)
						if pkgs.ConfigByKey(pkgver) == nil {
							continue
						}

						if err := renderNode(pkgver); err != nil {
							return nil, err
						}
					}
				}

				return out, nil
			}

			if web {
				http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/" {
						return
					}
					nodes := r.URL.Query()["node"]

					if len(nodes) == 0 {
						nodes = args
					}

					out, err := render(nodes)
					if err != nil {
						fmt.Fprintf(w, "error rendering %v: %v", nodes, err)
						log.Fatal(err)
					}

					log.Printf("%s: rendering %v", r.URL, nodes)
					cmd := exec.Command("dot", "-Tsvg")
					cmd.Stdin = strings.NewReader(out.String())
					cmd.Stdout = w

					if err := cmd.Run(); err != nil {
						fmt.Fprintf(w, "error rendering %v: %v", nodes, err)
						log.Fatal(err)
					}
				})

				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					return err
				}

				server := &http.Server{
					Addr:              l.Addr().String(),
					ReadHeaderTimeout: 3 * time.Second,
				}

				log.Printf("%s", l.Addr().String())

				var g errgroup.Group
				g.Go(func() error {
					return server.Serve(l)
				})

				g.Go(func() error {
					return open.Run(fmt.Sprintf("http://localhost:%d", l.Addr().(*net.TCPAddr).Port))
				})

				return g.Wait()
			}

			out, err := render(args)
			if err != nil {
				return err
			}

			fmt.Println(out.String())
			return nil
		},
	}
	d.Flags().StringVarP(&dir, "dir", "d", ".", "directory to search for melange configs")
	d.Flags().StringVar(&pipelineDir, "pipeline-dir", "", "directory used to extend defined built-in pipelines")
	d.Flags().BoolVarP(&showDependents, "show-dependents", "D", false, "show packages that depend on these packages, instead of these packages' dependencies")
	d.Flags().BoolVarP(&recursive, "recursive", "R", false, "recurse through package dependencies")
	d.Flags().BoolVarP(&span, "spanning-tree", "S", false, "does something like a spanning tree to avoid a huge number of edges")
	d.Flags().BoolVar(&buildtimeReposForRuntime, "buildtime-repos-for-runtime", false, "use buildtime environment repositories to resolve runtime graph as well")
	d.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the build environment keyring")
	d.Flags().StringSliceVarP(&extraRepos, "repository-append", "r", []string{}, "path to extra repositories to include in the build environment")
	d.Flags().BoolVar(&web, "web", false, "do a website")
	return d
}

func split(in string) (pkgver, source string) {
	before, source, ok := strings.Cut(in, "@")
	if !ok {
		panic(in)
	}

	pkg, ver, ok := strings.Cut(before, ":")
	if !ok {
		panic(in)
	}

	return fmt.Sprintf("%s-%s", pkg, ver), source
}

func pop(a []string) (result string, stack []string) {
	return a[len(a)-1], a[:len(a)-1]
}

func link(args []string, pkgver string) string {
	filtered := []string{}
	for _, a := range args {
		if a != pkgver {
			filtered = append(filtered, a)
		}
	}
	return "/?node=" + pkgver + "&node=" + strings.Join(filtered, "&node=")
}
