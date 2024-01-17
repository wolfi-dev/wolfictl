package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/config"
	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"

	"github.com/wolfi-dev/wolfictl/pkg/dag"
	"golang.org/x/sync/errgroup"
)

func cmdBuild() *cobra.Command {
	var archs []string
	var dir, pipelineDir, runner, logDir string
	var jobs int
	var dryrun bool
	var extraKeys, extraRepos []string

	// TODO: buildworld bool (build deps vs get them from package repo)
	// TODO: builddownstream bool (build things that depend on listed packages)
	cmd := &cobra.Command{
		Use:           "build",
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			log := clog.FromContext(ctx)

			if jobs == 0 {
				jobs = runtime.GOMAXPROCS(0)
			}
			jobch := make(chan struct{}, jobs)

			if pipelineDir == "" {
				pipelineDir = filepath.Join(dir, "pipelines")
			}

			newTask := func(pkg string) *task {
				return &task{
					pkg:         pkg,
					dir:         dir,
					pipelineDir: pipelineDir,
					runner:      runner,
					archs:       archs,
					dryrun:      dryrun,
					done:        make(chan struct{}),
					deps:        map[string]chan struct{}{},
					jobch:       jobch,
					logDir:      logDir,
				}
			}

			pkgs, err := dag.NewPackages(ctx, os.DirFS(dir), dir, pipelineDir)
			if err != nil {
				return err
			}
			g, err := dag.NewGraph(ctx, pkgs,
				dag.WithKeys(extraKeys...),
				dag.WithRepos(extraRepos...))
			if err != nil {
				return err
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
					// The package list is in the form of "pkg:version",
					// but we only care about the package name.
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

			for _, t := range tasks {
				go t.start(ctx)
			}
			count := len(tasks)

			for _, t := range tasks {
				if err := t.wait(ctx); err != nil {
					return fmt.Errorf("failed to build %s: %w", t.pkg, err)
				}
				delete(tasks, t.pkg)
				log.Infof("Finished building %s (%d/%d)", t.pkg, count-len(tasks), count)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&dir, "dir", "d", ".", "directory to search for melange configs")
	cmd.Flags().StringVar(&pipelineDir, "pipeline-dir", "", "directory used to extend defined built-in pipelines")
	cmd.Flags().StringVar(&runner, "runner", "docker", "which runner to use to enable running commands, default is based on your platform.")
	cmd.Flags().IntVarP(&jobs, "jobs", "j", 0, "number of jobs to run concurrently (default is GOMAXPROCS)")
	cmd.Flags().StringSliceVar(&archs, "arch", []string{"x86_64", "aarch64"}, "arch of package to build")
	cmd.Flags().BoolVar(&dryrun, "dry-run", false, "print commands instead of executing them")
	cmd.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"}, "path to extra keys to include in the build environment keyring")
	cmd.Flags().StringSliceVarP(&extraRepos, "repository-append", "r", []string{"https://packages.wolfi.dev/os"}, "path to extra repositories to include in the build environment")
	cmd.Flags().StringVar(&logDir, "log-dir", "buildlogs", "subdirectory where buildlogs will be written when specified (packages/$arch/buildlogs/$apk.log)")
	return cmd
}

type task struct {
	pkg, dir, pipelineDir, runner, logDir string
	archs                                 []string
	dryrun                                bool

	err         error
	deps        map[string]chan struct{}
	done, jobch chan struct{}
}

func (t *task) start(ctx context.Context) {
	log := clog.FromContext(ctx).With("pkg", t.pkg)
	log.Infof("task %q waiting on %q", t.pkg, maps.Keys(t.deps))

	defer close(t.done) // signal that we're done, one way or another.
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for depname, dep := range t.deps {
		select {
		case <-tick.C:
			log.Infof("task %q waiting on %q", t.pkg, maps.Keys(t.deps))
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
	t.err = t.do(ctx)
}

func (t *task) do(ctx context.Context) error {
	cfg, err := config.ParseConfiguration(ctx, fmt.Sprintf("%s.yaml", t.pkg), config.WithFS(os.DirFS(t.dir)))
	if err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	var bcs []*build.Build
	for _, arch := range t.archs {
		log := clog.New(slog.Default().Handler()).With("arch", arch)
		ctx := clog.WithLogger(ctx, log)

		// See if we already have the package built.
		apk := fmt.Sprintf("%s-%s-r%d.apk", cfg.Package.Name, cfg.Package.Version, cfg.Package.Epoch)
		apkPath := filepath.Join(t.dir, "packages", arch, apk)
		if _, err := os.Stat(apkPath); err == nil {
			log.Infof("skipping %s, already built", apkPath)
			continue
		}

		sdir := filepath.Join(t.dir, t.pkg)
		if _, err := os.Stat(sdir); os.IsNotExist(err) {
			if err := os.MkdirAll(sdir, os.ModePerm); err != nil {
				return fmt.Errorf("creating source directory %s: %v", sdir, err)
			}
		} else if err != nil {
			return fmt.Errorf("creating source directory: %v", err)
		}

		logPolicy := []string{"builtin:stderr"}
		if t.logDir != "" {
			// mirror wolfi/os Makefile semantics of: ./packages/$arch/buildlogs/$apk.log
			logPolicy = append(logPolicy, fmt.Sprintf("%s/%s.log",
				filepath.Join(t.dir, "packages", string(types.ParseArchitecture(arch)), t.logDir),
				apk,
			))
		}

		fn := fmt.Sprintf("%s.yaml", t.pkg)
		if t.dryrun {
			log.Infof("DRYRUN: would have built %s", apkPath)
			continue
		}
		log.Infof("will build: %s", apkPath)
		bc, err := build.New(ctx,
			build.WithArch(types.ParseArchitecture(arch)),
			build.WithConfig(filepath.Join(t.dir, fn)),
			build.WithPipelineDir(t.pipelineDir),
			build.WithExtraKeys([]string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"}),
			build.WithExtraRepos([]string{"https://packages.wolfi.dev/os"}),
			build.WithSigningKey(filepath.Join(t.dir, "local-melange.rsa")),
			build.WithRunner(t.runner),
			build.WithEnvFile(filepath.Join(t.dir, fmt.Sprintf("build-%s.env", arch))),
			build.WithNamespace("wolfi"),
			build.WithLogPolicy(logPolicy),
			build.WithSourceDir(sdir),
			build.WithCacheSource("gs://wolfi-sources/"),
			build.WithCacheDir("./melange-cache/"), // TODO: flag
			build.WithOutDir(filepath.Join(t.dir, "packages")),
		)
		if err != nil {
			return err
		}
		bcs = append(bcs, bc)
	}
	var errg errgroup.Group
	for _, bc := range bcs {
		bc := bc
		errg.Go(func() error {
			return bc.BuildPackage(ctx)
		})
	}
	return errg.Wait()
}

func (t *task) wait(ctx context.Context) error {
	select {
	case <-t.done:
		return t.err
	case <-ctx.Done():
		return ctx.Err()
	}
}
