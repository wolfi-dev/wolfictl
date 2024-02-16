package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/container"
	"chainguard.dev/melange/pkg/container/docker"
	"github.com/chainguard-dev/clog"
	charmlog "github.com/charmbracelet/log"
	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"

	"github.com/wolfi-dev/wolfictl/pkg/dag"
	"golang.org/x/sync/errgroup"
)

func cmdBuild() *cobra.Command {
	var archs []string
	var dir, pipelineDir, runner string
	var jobs int
	var dryrun bool
	var extraKeys, extraRepos []string

	// TODO: allow building only named packages, taking deps into account.
	// TODO: buildworld bool (build deps vs get them from package repo)
	// TODO: builddownstream bool (build things that depend on listed packages)
	cmd := &cobra.Command{
		Use:           "build",
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			if jobs == 0 {
				jobs = runtime.GOMAXPROCS(0)
			}
			jobch := make(chan struct{}, jobs)

			if pipelineDir == "" {
				pipelineDir = filepath.Join(dir, "pipelines")
			}

			// Logs will go here to mimic the wolfi Makefile.
			for _, arch := range archs {
				archDir := logdir(dir, arch)
				if err := os.MkdirAll(archDir, os.ModePerm); err != nil {
					return fmt.Errorf("creating buildlogs directory: %w", err)
				}
			}

			newTask := func(pkg string) *task {
				return &task{
					pkg:         pkg,
					dir:         dir,
					pipelineDir: pipelineDir,
					runner:      runner,
					archs:       archs,
					dryrun:      dryrun,
					cond:        sync.NewCond(&sync.Mutex{}),
					deps:        map[string]*task{},
					jobch:       jobch,
				}
			}

			// We want to ignore info level here during setup, but further down below we pull whatever was passed to use via ctx.
			log := clog.New(charmlog.NewWithOptions(os.Stderr, charmlog.Options{ReportTimestamp: true, Level: charmlog.WarnLevel}))
			setupCtx := clog.WithLogger(ctx, log)
			pkgs, err := dag.NewPackages(setupCtx, os.DirFS(dir), dir, pipelineDir)
			if err != nil {
				return err
			}
			g, err := dag.NewGraph(setupCtx, pkgs,
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
							tasks[pkg].deps[d] = tasks[d]
						}
					}
				}
			}

			if len(tasks) == 0 {
				return fmt.Errorf("no packages to build")
			}

			for _, t := range tasks {
				t.maybeStart(ctx)
			}
			count := len(tasks)

			// We're ok with Info level from here on.
			log = clog.FromContext(ctx)

			errs := []error{}
			for _, t := range tasks {
				if err := t.wait(); err != nil {
					errs = append(errs, fmt.Errorf("failed to build %s: %w", t.pkg, err))
					continue
				}

				delete(tasks, t.pkg)
				log.Infof("Finished building %s (%d/%d)", t.pkg, count-len(tasks), count)
			}

			// If the context is cancelled, it's not useful to print everything, just summarize the count.
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("failed to build %d packages: %w", len(errs), err)
			}

			return errors.Join(errs...)
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
	return cmd
}

type task struct {
	pkg, dir, pipelineDir, runner string
	archs                         []string
	dryrun                        bool

	err  error
	deps map[string]*task

	cond    *sync.Cond
	started bool
	done    bool

	jobch chan struct{}
}

func (t *task) start(ctx context.Context) {
	defer func() {
		// When we finish, wake up any goroutines that are waiting on us.
		t.cond.L.Lock()
		t.done = true
		t.cond.Broadcast()
		t.cond.L.Unlock()
	}()

	for _, dep := range t.deps {
		dep.maybeStart(ctx)
	}

	log := clog.FromContext(ctx).With("pkg", t.pkg)
	log.Infof("task %q waiting on %q", t.pkg, maps.Keys(t.deps))

	for _, dep := range t.deps {
		if err := dep.wait(); err != nil {
			t.err = err
			return
		}
	}

	// Block on jobch, to limit concurrency. Remove from jobch when done.
	t.jobch <- struct{}{}
	defer func() { <-t.jobch }()

	// all deps are done and we're clear to launch.
	t.err = t.build(ctx)
}

func (t *task) build(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	log := clog.FromContext(ctx)
	cfg, err := config.ParseConfiguration(ctx, fmt.Sprintf("%s.yaml", t.pkg), config.WithFS(os.DirFS(t.dir)))
	if err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	var errg errgroup.Group
	for _, arch := range t.archs {
		arch := types.ParseArchitecture(arch).ToAPK()

		pkgver := fmt.Sprintf("%s-%s-r%d", cfg.Package.Name, cfg.Package.Version, cfg.Package.Epoch)
		logDir := logdir(t.dir, arch)
		logfile := filepath.Join(logDir, pkgver) + ".log"

		// See if we already have the package built.
		apk := pkgver + ".apk"
		apkPath := filepath.Join(t.dir, "packages", arch, apk)
		if _, err := os.Stat(apkPath); err == nil {
			log.Infof("skipping %s, already built", apkPath)
			continue
		}

		f, err := os.Create(logfile)
		if err != nil {
			return fmt.Errorf("creating logfile: :%w", err)
		}
		defer f.Close()

		log := clog.New(slog.NewTextHandler(f, nil)).With("package", t.pkg)
		fctx := clog.WithLogger(ctx, log)

		if len(t.archs) > 1 {
			log = clog.New(log.Handler()).With("arch", arch)
			fctx = clog.WithLogger(fctx, log)
		}

		sdir := filepath.Join(t.dir, t.pkg)
		if _, err := os.Stat(sdir); os.IsNotExist(err) {
			if err := os.MkdirAll(sdir, os.ModePerm); err != nil {
				return fmt.Errorf("creating source directory %s: %v", sdir, err)
			}
		} else if err != nil {
			return fmt.Errorf("creating source directory: %v", err)
		}

		fn := fmt.Sprintf("%s.yaml", t.pkg)
		if t.dryrun {
			log.Infof("DRYRUN: would have built %s", apkPath)
			continue
		}

		runner, err := newRunner(fctx, t.runner)
		if err != nil {
			return fmt.Errorf("creating runner: %w", err)
		}

		log.Infof("will build: %s", apkPath)
		bc, err := build.New(fctx,
			build.WithArch(types.ParseArchitecture(arch)),
			build.WithConfig(filepath.Join(t.dir, fn)),
			build.WithPipelineDir(t.pipelineDir),
			build.WithExtraKeys([]string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"}), // TODO: flag
			build.WithExtraRepos([]string{"https://packages.wolfi.dev/os"}),                      // TODO: flag
			build.WithSigningKey(filepath.Join(t.dir, "local-melange.rsa")),
			build.WithRunner(runner),
			build.WithEnvFile(filepath.Join(t.dir, fmt.Sprintf("build-%s.env", arch))),
			build.WithNamespace("wolfi"), // TODO: flag
			build.WithSourceDir(sdir),
			build.WithCacheSource("gs://wolfi-sources/"), // TODO: flag
			build.WithCacheDir("./melange-cache/"),       // TODO: flag
			build.WithOutDir(filepath.Join(t.dir, "packages")),
			build.WithRemove(true),
		)
		if err != nil {
			return err
		}
		defer func() {
			// We Close() with the original context if we're cancelled so we get cleanup logs to stderr.
			ctx := ctx
			if ctx.Err() == nil {
				// On happy path, we don't care about cleanup logs.
				ctx = fctx
			}

			if err := bc.Close(ctx); err != nil {
				log.Errorf("closing build %q: %v", t.pkg, err)
			}
		}()
		errg.Go(func() error {
			return bc.BuildPackage(fctx)
		})
	}
	return errg.Wait()
}

// If this task hasn't already been started, start it.
func (t *task) maybeStart(ctx context.Context) {
	t.cond.L.Lock()
	defer t.cond.L.Unlock()

	if !t.started {
		t.started = true
		go t.start(ctx)
	}
}

// Park the calling goroutine until this task finishes.
func (t *task) wait() error {
	t.cond.L.Lock()
	for !t.done {
		t.cond.Wait()
	}
	t.cond.L.Unlock()

	return t.err
}

func newRunner(ctx context.Context, runner string) (container.Runner, error) {
	switch runner {
	case "docker":
		return docker.NewRunner(ctx)
	case "bubblewrap":
		return container.BubblewrapRunner(), nil
	}

	return nil, fmt.Errorf("runner %q not supported", runner)
}

func logdir(dir, arch string) string {
	return filepath.Join(dir, "packages", arch, "buildlogs")
}
