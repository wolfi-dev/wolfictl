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
	"golang.org/x/exp/slices"
	"golang.org/x/sync/errgroup"

	"github.com/skratchdot/open-golang/open"
)

func cmdSVG() *cobra.Command { //nolint:gocyclo
	var dir, pipelineDir string
	var showDependents, buildtimeReposForRuntime, web bool
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

			amap, err := g.Graph.AdjacencyMap()
			if err != nil {
				return err
			}

			pmap, err := g.Graph.PredecessorMap()
			if err != nil {
				return err
			}

			render := func(args []string) (*dot.Graph, error) {
				out := dot.NewGraph("images")
				if err := out.Set("rankdir", "LR"); err != nil {
					return nil, err
				}
				out.SetType(dot.DIGRAPH)

				for _, node := range args {
					var byName []dag.Package
					config := pkgs.ConfigByKey(node)
					if config != nil {
						byName = append(byName, config)
					} else {
						byName, err = g.NodesByName(node)
						if err != nil {
							return nil, err
						}

						if len(byName) == 0 {
							return nil, fmt.Errorf("could not find node %q", node)
						}
					}

					for _, name := range byName {
						pkgver, source := split(dag.PackageHash(name))
						n := dot.NewNode(pkgver)
						if err := n.Set("tooltip", source); err != nil {
							return nil, err
						}
						out.AddNode(n)

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
							pkgver, source := split(dep)
							d := dot.NewNode(pkgver)
							if err := d.Set("tooltip", source); err != nil {
								return nil, err
							}
							if web {
								nodes := slices.Clone(args)
								nodes = append(nodes, pkgver)

								if pkgs.ConfigByKey(pkgver) != nil {
									if err := d.Set("URL", "/?node="+strings.Join(nodes, "&node=")); err != nil {
										return nil, err
									}
								}
							}
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
							pkgver, source := split(pred)
							d := dot.NewNode(pkgver)
							if err := d.Set("tooltip", source); err != nil {
								return nil, err
							}
							if web {
								nodes := slices.Clone(args)
								nodes = append(nodes, pkgver)

								if pkgs.ConfigByKey(pkgver) != nil {
									if err := d.Set("URL", "/?node="+strings.Join(nodes, "&node=")); err != nil {
										return nil, err
									}
								}
							}
							out.AddNode(d)
							out.AddEdge(dot.NewEdge(d, n))
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
