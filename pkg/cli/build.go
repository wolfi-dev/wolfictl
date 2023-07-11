package cli

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/dag"
	"golang.org/x/exp/maps"
)

func Build() *cobra.Command {
	var archs []string
	var dir, pipelineDir string
	var jobs int
	var dryrun bool
	cmd := &cobra.Command{
		Use:           "build",
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			if jobs == 0 {
				jobs = runtime.GOMAXPROCS(0)
			}
			jobch := make(chan struct{}, jobs)

			newTask := func(pkg string) *task {
				return &task{
					pkg:         pkg,
					dir:         dir,
					pipelineDir: pipelineDir,
					stdout:      cmd.OutOrStdout(),
					stderr:      cmd.ErrOrStderr(),
					dryrun:      dryrun,
					done:        make(chan struct{}),
					deps:        map[string]chan struct{}{},
					jobch:       jobch,
				}
			}

			if len(args) == 1 {
				// Build only this one package.
				t := newTask(args[0])
				go t.start(ctx)
				return t.wait(ctx)
			}

			pkgs, err := dag.NewPackages(os.DirFS(dir), dir, pipelineDir)
			if err != nil {
				return err
			}
			g, err := dag.NewGraph(pkgs)
			if err != nil {
				return err
			}
			if len(args) > 1 {
				// If multiple args were passed, build only the subgraph based on these packages.
				g, err = g.SubgraphWithRoots(args)
				if err != nil {
					return err
				}
			}
			// Only return local packages
			g, err = g.Filter(dag.FilterLocal())
			if err != nil {
				return err
			}

			// Only return main packages (configs)
			g, err = g.Filter(dag.OnlyMainPackages(pkgs))
			if err != nil {
				return err
			}

			m, err := g.Graph.AdjacencyMap()
			if err != nil {
				return err
			}

			tasks := map[string]*task{}
			for _, pkg := range g.Packages() {
				if tasks[pkg] == nil {
					tasks[pkg] = newTask(pkg)
				}
				for k, v := range m {
					if strings.HasPrefix(k, pkg+":") {
						for _, dep := range v {
							d, _, _ := strings.Cut(dep.Target, ":")

							if tasks[d] == nil {
								tasks[d] = newTask(d)
							}
							tasks[pkg].deps[d] = tasks[d].done
						}
					}
				}
			}

			if len(tasks) == 0 {
				return fmt.Errorf("no packages to build")
			}

			// TODO: limit concurrency, without starving the graph.
			for _, t := range tasks {
				go t.start(ctx)
			}
			count := len(tasks)

			for _, t := range tasks {
				if err := t.wait(ctx); err != nil {
					return fmt.Errorf("failed to build %s: %w", t.pkg, err)
				}
				delete(tasks, t.pkg)
				log.Printf("DONE %s (%d/%d)", t.pkg, count-len(tasks), count)
			}
			log.Println("ALL DONE!!")
			return nil
		},
	}

	cmd.Flags().StringVarP(&dir, "dir", "d", ".", "directory to search for melange configs")
	cmd.Flags().StringVar(&pipelineDir, "pipeline-dir", "", "directory used to extend defined built-in pipelines")
	cmd.Flags().IntVarP(&jobs, "jobs", "j", 0, "number of jobs to run concurrently (default is GOMAXPROCS)")
	cmd.Flags().StringSliceVar(&archs, "arch", []string{"x86_64", "aarch64"}, "arch of package to build") // TODO: actually use this
	cmd.Flags().BoolVar(&dryrun, "dry-run", false, "print commands instead of executing them")
	return cmd
}

type task struct {
	pkg, dir, pipelineDir string
	stdout, stderr        io.Writer
	dryrun                bool

	err         error
	deps        map[string]chan struct{}
	done, jobch chan struct{}
}

func (t *task) start(ctx context.Context) {
	log.Printf("task %q waiting on %q", t.pkg, maps.Keys(t.deps))

	defer close(t.done) // signal that we're done, one way or another.
	tick := time.NewTicker(30 * time.Second)
	for depname, dep := range t.deps {
		select {
		case <-tick.C:
			log.Printf("task %q waiting on %q", t.pkg, maps.Keys(t.deps))
		case <-dep:
			delete(t.deps, depname)
			// this dep is done.
		case <-ctx.Done():
			return // cancelled or failed
		}
	}

	// Block on jobch, to limit concurrency. Remove from jobch when done.
	t.jobch <- struct{}{}
	defer func() { <-t.jobch }()

	// all deps are done and we're clear to launch.
	t.do(ctx)
}

func (t *task) do(ctx context.Context) {
	// TODO: remove make indirection, invoke melange directly as a library.
	// TODO: pass --pipeline-dir to melange; until then, skip ko-fips
	if t.pkg == "ko-fips" {
		return
	}
	c := exec.CommandContext(ctx, "make", "BUILDWORLD=no", "MELANGE_EXTRA_OPTS=--runner=kubernetes", fmt.Sprintf("package/%s", t.pkg)) //nolint:gosec
	c.Dir = t.dir
	fmt.Fprintln(t.stderr, c.String())
	if t.dryrun {
		time.Sleep(time.Duration(rand.Intn(3000)) * time.Millisecond)
		return
	}

	c.Stdout = t.stdout
	c.Stderr = t.stderr
	t.err = c.Run()
}

func (t *task) wait(ctx context.Context) error {
	select {
	case <-t.done:
		return t.err
	case <-ctx.Done():
		return ctx.Err()
	}
}
