package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/build"
	"github.com/chainguard-dev/clog"
	charmlog "github.com/charmbracelet/log"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/dag"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/trace"
	"golang.org/x/sync/errgroup"
)

func cmdTest() *cobra.Command {
	var traceFile string

	cfg := testConfig{}

	cmd := &cobra.Command{
		Use:  "test",
		Long: `Test wolfi packages. Accepts either no positional arguments (for testing everything) or a list of packages to test.`,
		Example: `
    # Test everything for every x86_64 and aarch64
    wolfictl test

    # Test a few packages
    wolfictl test \
      --arch aarch64 \
      hello-wolfi wget


    # Test a single local package
    wolfictl test \
      --arch aarch64 \
      -k local-melange.rsa.pub \
      -r ./packages \
      -r https://packages.wolfi.dev/os \
      -k https://packages.wolfi.dev/os/wolfi-signing.rsa.pub \
      hello-wolfi
    `,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			if traceFile != "" {
				w, err := os.Create(traceFile)
				if err != nil {
					return fmt.Errorf("creating trace file: %w", err)
				}
				defer w.Close()
				exporter, err := stdouttrace.New(stdouttrace.WithWriter(w))
				if err != nil {
					return fmt.Errorf("creating stdout exporter: %w", err)
				}
				tp := trace.NewTracerProvider(trace.WithBatcher(exporter))
				otel.SetTracerProvider(tp)

				defer func() {
					if err := tp.Shutdown(context.WithoutCancel(ctx)); err != nil {
						clog.FromContext(ctx).Errorf("Shutting down trace provider: %v", err)
					}
				}()

				tctx, span := otel.Tracer("wolfictl").Start(ctx, "test")
				defer span.End()
				ctx = tctx
			}

			if cfg.jobs == 0 {
				cfg.jobs = runtime.GOMAXPROCS(0)
			}

			if cfg.pipelineDir == "" {
				cfg.pipelineDir = filepath.Join(cfg.dir, "pipelines")
			}
			if cfg.outDir == "" {
				cfg.outDir = filepath.Join(cfg.dir, "packages")
			}

			if cfg.cacheDir != "" {
				if err := os.MkdirAll(cfg.cacheDir, os.ModePerm); err != nil {
					return fmt.Errorf("creating cache directory: %w", err)
				}
			}

			return testAll(ctx, &cfg, args)
		},
	}

	cmd.Flags().StringVarP(&cfg.dir, "dir", "d", ".", "directory to search for melange configs")
	cmd.Flags().StringVar(&cfg.pipelineDir, "pipeline-dir", "./pipelines", "directory used to extend defined built-in pipelines")
	cmd.Flags().StringVar(&cfg.runner, "runner", "docker", "which runner to use to enable running commands, default is based on your platform.")
	cmd.Flags().StringSliceVar(&cfg.archs, "arch", []string{"x86_64", "aarch64"}, "arch of package to build")
	cmd.Flags().StringSliceVarP(&cfg.extraKeys, "keyring-append", "k", []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"}, "path to extra keys to include in the build environment keyring")
	cmd.Flags().StringSliceVarP(&cfg.extraRepos, "repository-append", "r", []string{"https://packages.wolfi.dev/os"}, "path to extra repositories to include in the build environment")
	cmd.Flags().StringSliceVar(&cfg.extraPackages, "test-package-append", []string{"wolfi-base"}, "extra packages to install for each of the test environments")
	cmd.Flags().StringVar(&cfg.cacheDir, "cache-dir", "./melange-cache/", "directory used for cached inputs")
	cmd.Flags().StringVar(&cfg.cacheSource, "cache-source", "", "directory or bucket used for preloading the cache")
	cmd.Flags().StringVar(&cfg.dst, "destination-repository", "", "repo where packages will eventually be uploaded, used to skip existing packages (currently only supports http)")
	cmd.Flags().BoolVar(&cfg.debug, "debug", true, "enable test debug logging")

	cmd.Flags().IntVarP(&cfg.jobs, "jobs", "j", 0, "number of jobs to run concurrently (default is GOMAXPROCS)")
	cmd.Flags().StringVar(&traceFile, "trace", "", "where to write trace output")

	return cmd
}

type testConfig struct {
	archs         []string
	extraKeys     []string
	extraRepos    []string
	extraPackages []string

	outDir      string // used for keeping logs consistent with build
	dir         string
	dst         string
	pipelineDir string
	runner      string
	debug       bool

	cacheSource string
	cacheDir    string

	jobs int
}

func testAll(ctx context.Context, cfg *testConfig, packages []string) error {
	log := clog.FromContext(ctx)

	pkgs, err := cfg.getPackages(ctx)
	if err != nil {
		return fmt.Errorf("getting packages: %w", err)
	}

	todoPkgs := make(map[string]struct{}, len(packages))
	for _, pkg := range packages {
		todoPkgs[pkg] = struct{}{}
	}

	archs := make([]types.Architecture, 0, len(cfg.archs))
	for _, arch := range cfg.archs {
		archs = append(archs, types.ParseArchitecture(arch))

		archDir := cfg.logDir(arch)
		if err := os.MkdirAll(archDir, os.ModePerm); err != nil {
			return fmt.Errorf("creating buildlogs directory: %w", err)
		}
	}

	eg, ctx := errgroup.WithContext(ctx)
	if cfg.jobs > 0 {
		log.Info("Limiting max jobs", "jobs", cfg.jobs)
		eg.SetLimit(cfg.jobs)
	}

	// If only one package or sequential tests, log to stdout, otherwise log to files
	logStdout := len(packages) == 1 || cfg.jobs == 1

	failures := testFailures{}

	// We don't care about the actual dag deps, so we use a simple fan-out
	for _, pkg := range pkgs.Packages() {
		if _, ok := todoPkgs[pkg.Name()]; len(todoPkgs) > 0 && !ok {
			log.Debugf("Skipping package %q", pkg)
			continue
		}

		pkg := pkg

		for _, arch := range archs {
			arch := arch

			eg.Go(func() error {
				log.Infof("Testing %s", pkg.Name())

				pctx := ctx
				if !logStdout {
					logf, err := cfg.packageLogFile(pkg, arch.ToAPK())
					if err != nil {
						return fmt.Errorf("creating log file: %w", err)
					}
					defer logf.Close()

					pctx = clog.WithLogger(pctx,
						clog.New(slog.NewTextHandler(logf, nil)),
					)
				}

				if err := testArch(pctx, cfg, pkg, arch); err != nil {
					log.Errorf("Testing package: %s: %q", pkg.Name(), err)
					failures.add(pkg.Name())
				}

				return nil
			})
		}
	}

	if err := eg.Wait(); err != nil {
		return err
	}

	log.Info("Finished testing packages")

	if failures.count > 0 {
		log.Fatalf("failed to test %d packages", failures.count)
	}

	return nil
}

func testArch(ctx context.Context, cfg *testConfig, pkgCfg *dag.Configuration, arch types.Architecture) error {
	ctx, span := otel.Tracer("wolifctl").Start(ctx, pkgCfg.Package.Name)
	defer span.End()

	runner, err := newRunner(ctx, cfg.runner)
	if err != nil {
		return fmt.Errorf("creating runner: %w", err)
	}

	sdir, err := pkgSourceDir(cfg.dir, pkgCfg.Package.Name)
	if err != nil {
		return fmt.Errorf("creating source directory: %w", err)
	}

	tc, err := build.NewTest(ctx,
		build.WithTestArch(arch),
		build.WithTestConfig(pkgCfg.Path),
		build.WithTestPipelineDir(cfg.pipelineDir),
		build.WithTestExtraKeys(cfg.extraKeys),
		build.WithTestExtraRepos(cfg.extraRepos),
		build.WithExtraTestPackages(cfg.extraPackages),
		build.WithTestRunner(runner),
		build.WithTestSourceDir(sdir),
		build.WithTestCacheDir(cfg.cacheDir),
		build.WithTestCacheSource(cfg.cacheSource),
		build.WithTestDebug(cfg.debug),
	)
	if err != nil {
		return fmt.Errorf("creating tester: %w", err)
	}
	defer tc.Close()

	if err := tc.TestPackage(ctx); err != nil {
		return err
	}

	return nil
}

func (c *testConfig) getPackages(ctx context.Context) (*dag.Packages, error) {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, "getPackages")
	defer span.End()

	// We want to ignore info level here during setup, but further down below we pull whatever was passed to use via ctx.
	log := clog.New(charmlog.NewWithOptions(os.Stderr, charmlog.Options{ReportTimestamp: true, Level: charmlog.WarnLevel}))
	ctx = clog.WithLogger(ctx, log)

	pkgs, err := dag.NewPackages(ctx, os.DirFS(c.dir), c.dir, c.pipelineDir)
	if err != nil {
		return nil, fmt.Errorf("parsing packages: %w", err)
	}

	return pkgs, nil
}

func (c *testConfig) logDir(arch string) string {
	return filepath.Join(c.outDir, arch, "testlogs")
}

func (c *testConfig) packageLogFile(pkg *dag.Configuration, arch string) (io.WriteCloser, error) {
	logDir := c.logDir(arch)

	if err := os.MkdirAll(logDir, os.ModePerm); err != nil {
		return nil, fmt.Errorf("creating log directory: %w", err)
	}

	filePath := filepath.Join(logDir, fmt.Sprintf("%s.test.log", pkg.FullName()))

	f, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("creating log file: %w", err)
	}

	return f, nil
}

func pkgSourceDir(workspaceDir, pkgName string) (string, error) {
	sdir := filepath.Join(workspaceDir, pkgName)
	if _, err := os.Stat(sdir); os.IsNotExist(err) {
		if err := os.MkdirAll(sdir, os.ModePerm); err != nil {
			return "", fmt.Errorf("creating source directory %s: %v", sdir, err)
		}
	} else if err != nil {
		return "", fmt.Errorf("creating source directory: %v", err)
	}

	return sdir, nil
}

type testFailures struct {
	mu       sync.Mutex
	failures []string
	count    int
}

func (t *testFailures) add(fail string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.count++
	t.failures = append(t.failures, fail)
}
