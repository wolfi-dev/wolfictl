package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/container"
	"chainguard.dev/melange/pkg/container/docker"
	"chainguard.dev/melange/pkg/index"
	"chainguard.dev/melange/pkg/sign"
	"cloud.google.com/go/storage"
	"github.com/chainguard-dev/clog"
	charmlog "github.com/charmbracelet/log"
	"github.com/dominikbraun/graph"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/trace"
	"golang.org/x/exp/maps"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	"google.golang.org/api/option"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/wolfi-dev/wolfictl/pkg/dag"
	"github.com/wolfi-dev/wolfictl/pkg/internal/bundle"
	"github.com/wolfi-dev/wolfictl/pkg/tar"
)

func cmdBuild() *cobra.Command {
	var jobs int
	var traceFile string

	cfg := global{}

	// TODO: buildworld bool (build deps vs get them from package repo)
	// TODO: builddownstream bool (build things that depend on listed packages)
	cmd := &cobra.Command{
		Use:           "build",
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

				tctx, span := otel.Tracer("wolfictl").Start(ctx, "build")
				defer span.End()
				ctx = tctx
			}

			if jobs == 0 {
				jobs = runtime.GOMAXPROCS(0)
			}
			cfg.jobch = make(chan struct{}, jobs)
			cfg.donech = make(chan *task, jobs)

			if cfg.signingKey == "" {
				cfg.signingKey = filepath.Join(cfg.dir, "local-melange.rsa")
			}
			if cfg.pipelineDir == "" {
				cfg.pipelineDir = filepath.Join(cfg.dir, "pipelines")
			}
			if cfg.outDir == "" {
				cfg.outDir = filepath.Join(cfg.dir, "packages")
			}

			// Trying to avoid this error:
			// The object <object> exceeded the rate limit for object mutation operations (create, update, and delete).
			// Please reduce your request rate.
			// See https://cloud.google.com/storage/docs/gcs429.
			cfg.writeLimiters = map[string]*rate.Limiter{}
			for _, arch := range cfg.archs {
				cfg.writeLimiters[arch] = rate.NewLimiter(rate.Every(1*time.Second), 1)
			}

			// Used to track expected generation of index file to allow idempotent writes.
			cfg.generations = map[string]int64{}

			if cfg.bundle != "" {
				if cfg.stagingBucket == "" {
					return fmt.Errorf("need --bucket with --bundle")
				}

				client, err := storage.NewClient(ctx, option.WithTelemetryDisabled())
				if err != nil {
					return fmt.Errorf("creating gcs client: %w", err)
				}
				cfg.gcs = client

				return buildBundles(ctx, &cfg, cfg.bundle)
			}

			return buildAll(ctx, &cfg, args)
		},
	}

	cmd.Flags().StringVarP(&cfg.dir, "dir", "d", ".", "directory to search for melange configs")
	cmd.Flags().StringVar(&cfg.pipelineDir, "pipeline-dir", "", "directory used to extend defined built-in pipelines")
	cmd.Flags().StringVar(&cfg.runner, "runner", "docker", "which runner to use to enable running commands, default is based on your platform.")
	cmd.Flags().StringSliceVar(&cfg.archs, "arch", []string{"x86_64", "aarch64"}, "arch of package to build")
	cmd.Flags().BoolVar(&cfg.dryrun, "dry-run", false, "print commands instead of executing them")
	cmd.Flags().StringSliceVarP(&cfg.extraKeys, "keyring-append", "k", []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"}, "path to extra keys to include in the build environment keyring")
	cmd.Flags().StringSliceVarP(&cfg.extraRepos, "repository-append", "r", []string{"https://packages.wolfi.dev/os"}, "path to extra repositories to include in the build environment")
	cmd.Flags().StringVar(&cfg.signingKey, "signing-key", "", "key to use for signing")
	cmd.Flags().StringVar(&cfg.namespace, "namespace", "wolfi", "namespace to use in package URLs in SBOM (eg wolfi, alpine)")
	cmd.Flags().StringVar(&cfg.outDir, "out-dir", "", "directory where packages will be output")
	cmd.Flags().StringVar(&cfg.summary, "summary", "", "file to write build summary")
	cmd.Flags().StringVar(&cfg.cacheDir, "cache-dir", "./melange-cache/", "directory used for cached inputs")
	cmd.Flags().StringVar(&cfg.cacheSource, "cache-source", "", "directory or bucket used for preloading the cache")
	cmd.Flags().BoolVar(&cfg.generateIndex, "generate-index", true, "whether to generate APKINDEX.tar.gz")
	cmd.Flags().StringVar(&cfg.dst, "destination-repository", "", "repo where packages will eventually be uploaded, used to skip existing packages (currently only supports http)")
	cmd.Flags().StringVar(&cfg.dstBucket, "destination-bucket", "", "bucket where packages are uploaded (experimental)")
	cmd.Flags().StringVar(&cfg.bundle, "bundle", "", "bundle of work to do (experimental)")
	cmd.Flags().StringVar(&cfg.stagingBucket, "bucket", "", "gcs bucket to upload results (experimental)")

	cmd.Flags().IntVarP(&jobs, "jobs", "j", 0, "number of jobs to run concurrently (default is GOMAXPROCS)")
	cmd.Flags().StringVar(&traceFile, "trace", "", "where to write trace output")

	cmd.Flags().StringVar(&cfg.k8sNamespace, "k8s-namespace", "default", "namespace to deploy pods into for builds.")
	cmd.Flags().StringVar(&cfg.machineFamily, "machine-family", "", "machine family for amd64 builds")
	cmd.Flags().StringVar(&cfg.serviceAccount, "service-account", "default", "service-account to run pods as.")

	return cmd
}

type configStuff struct {
	g    *dag.Graph
	m    map[string]map[string]graph.Edge[string]
	pkgs *dag.Packages
}

func walkConfigs(ctx context.Context, cfg *global) (*configStuff, error) {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, "walkConfigs")
	defer span.End()

	// We want to ignore info level here during setup, but further down below we pull whatever was passed to use via ctx.
	log := clog.New(charmlog.NewWithOptions(os.Stderr, charmlog.Options{ReportTimestamp: true, Level: charmlog.WarnLevel}))
	ctx = clog.WithLogger(ctx, log)

	// Walk all the melange configs in cfg.dir, parses them, and builds the dependency graph of environment + pipelines (build time deps).
	pkgs, err := dag.NewPackages(ctx, os.DirFS(cfg.dir), cfg.dir, cfg.pipelineDir)
	if err != nil {
		return nil, err
	}

	g, err := dag.NewGraph(ctx, pkgs, dag.WithKeys(cfg.extraKeys...), dag.WithRepos(cfg.extraRepos...))
	if err != nil {
		return nil, err
	}

	// This drops any edges to non-local packages. This is a problem for bootstrap because things that depend
	// on bootstrap stages need to be run early.
	g, err = g.Filter(dag.FilterLocal())
	if err != nil {
		return nil, err
	}

	// Only return main packages (configs) because we can't build just subpackages.
	g, err = g.Targets()
	if err != nil {
		return nil, fmt.Errorf("targets: %w", err)
	}

	m, err := g.Graph.AdjacencyMap()
	if err != nil {
		return nil, err
	}

	return &configStuff{
		g:    g,
		m:    m,
		pkgs: pkgs,
	}, nil
}

func (g *global) fetchIndexFromBucket(ctx context.Context, arch string) (map[string]struct{}, error) {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, "fetchIndexFromBucket")
	defer span.End()

	exist := map[string]struct{}{}

	if g.dstBucket == "" {
		return exist, nil
	}

	obj := path.Join(arch, "APKINDEX.tar.gz")
	out := filepath.Join(g.outDir, arch, "APKINDEX.tar.gz")

	bucket, dir, ok := strings.Cut(g.dstBucket, "/")
	if ok {
		obj = path.Join(dir, obj)
	}

	rc, err := g.gcs.Bucket(bucket).Object(obj).NewReader(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return exist, nil
		}
		return nil, err
	}
	defer rc.Close()

	// Set this for conditional requests on upload.
	g.generations[arch] = rc.Attrs.Generation

	clog.FromContext(ctx).Debugf("downloading %s to %s", obj, out)

	f, err := os.Create(out)
	if err != nil {
		return nil, err
	}

	tee := io.TeeReader(rc, f)

	idx, err := apk.IndexFromArchive(io.NopCloser(tee))
	if err != nil {
		return nil, fmt.Errorf("parsing index %s: %w", obj, err)
	}

	for _, pkg := range idx.Packages {
		exist[pkg.Filename()] = struct{}{}
	}

	if _, err := io.Copy(io.Discard, tee); err != nil {
		return nil, err
	}

	if err := f.Close(); err != nil {
		return nil, f.Close()
	}

	return exist, nil
}

func fetchIndex(ctx context.Context, dst, arch string) (map[string]struct{}, error) {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, "fetchIndex")
	defer span.End()

	exist := map[string]struct{}{}
	if dst == "" {
		return exist, nil
	}

	// TODO: Support file paths. This is janky but we assume http for now because we need a better interface from go-apk.
	repo := apk.Repository{
		URI: fmt.Sprintf("%s/%s/%s", dst, arch, "APKINDEX.tar.gz"),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, repo.URI, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	idx, err := apk.IndexFromArchive(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parsing index %s: %w", repo.URI, err)
	}

	for _, pkg := range idx.Packages {
		exist[pkg.Filename()] = struct{}{}
	}

	return exist, nil
}

type buildResult struct {
	Package  string        `json:"package"`
	Pods     []string      `json:"pods,omitempty"`
	Duration time.Duration `json:"duration,omitempty"`
	Status   string        `json:"status,omitempty"`
	Error    error         `json:"error,omitempty"`
}

func buildBundles(ctx context.Context, cfg *global, ref string) error {
	var eg errgroup.Group

	bundles, err := bundle.Pull(ref)
	if err != nil {
		return err
	}

	var mu sync.Mutex
	cfg.exists = map[string]map[string]struct{}{}

	for _, arch := range cfg.archs {
		arch := types.ParseArchitecture(arch).ToAPK()

		if err := os.MkdirAll(filepath.Join(cfg.outDir, arch), os.ModePerm); err != nil {
			return fmt.Errorf("creating arch directory: %w", err)
		}

		// If --destination-repository or --destination-bucket is set, we want to fetch and parse the APKINDEXes concurrently with walking all the configs.
		eg.Go(func() error {
			exist, err := fetchIndex(ctx, cfg.dst, arch)
			if err != nil {
				return err
			}

			existBucket, err := cfg.fetchIndexFromBucket(ctx, arch)
			if err != nil {
				return err
			}

			for k, v := range existBucket {
				exist[k] = v
			}

			mu.Lock()
			defer mu.Unlock()

			cfg.exists[arch] = exist

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return err
	}

	newTask := func(pkg string, bundle bundle.Task, ref name.Digest) *task {
		return &task{
			cfg:    cfg,
			pkg:    pkg,
			ver:    bundle.Version,
			epoch:  bundle.Epoch,
			bundle: &bundle,
			ref:    &ref,
			archs:  filterArchs(cfg.archs, bundle.Architectures),
			cond:   sync.NewCond(&sync.Mutex{}),
			deps:   map[string]*task{},
		}
	}

	tasks := map[string]*task{}
	for _, btask := range bundles.Tasks { //nolint:gocritic
		tasks[btask.Package] = newTask(btask.Package, btask, bundles.Runtime)
	}

	for k, v := range bundles.Graph {
		// The package list is in the form of "pkg:version", but we only care about the package name.
		pkg, _, ok := strings.Cut(k, ":")
		if !ok {
			return fmt.Errorf("unexpected key: %q", k)
		}

		for _, dep := range v {
			d, _, ok := strings.Cut(dep.Target, ":")
			if !ok {
				return fmt.Errorf("unexpected dep: %q", dep)
			}

			tasks[pkg].deps[d] = tasks[d]
		}
	}

	if len(tasks) == 0 {
		return fmt.Errorf("no packages to build")
	}

	todos := tasks
	for _, t := range todos {
		t.maybeStart(ctx)
	}
	count := len(todos)

	// We're ok with Info level from here on.
	log := clog.FromContext(ctx)

	report := make([]*buildResult, 0, count)

	errs := []error{}
	skipped := 0

	for len(todos) != 0 {
		t := <-cfg.donech
		delete(todos, t.pkg)

		result := &buildResult{
			Package:  t.pkgver(),
			Pods:     t.pods,
			Duration: t.duration,
		}
		report = append(report, result)

		if err := t.err; err != nil {
			result.Error = err
			result.Status = "error"
			errs = append(errs, fmt.Errorf("failed to build %s: %w", t.pkg, err))
			log.Errorf("Failed to build %s (%d/%d)", t.pkg, len(errs), count)
			continue
		}

		// Logging every skipped package is too noisy, so we just print a summary
		// of the number of packages we skipped between actual builds.
		if t.skipped {
			result.Status = "skipped"
			skipped++
			continue
		} else if skipped != 0 {
			log.Infof("Skipped building %d packages", skipped)
			skipped = 0
		}

		result.Status = "ok"
		log.Infof("Finished building %s (%d/%d)", t.pkg, count-(len(todos)+len(errs)), count)
	}

	if skipped != 0 {
		log.Infof("Skipped building %d packages", skipped)
	}

	if cfg.summary != "" {
		out := os.Stdout
		if cfg.summary != "-" {
			f, err := os.Create(cfg.summary)
			if err != nil {
				return err
			}

			out = f
		}
		if err := json.NewEncoder(out).Encode(report); err != nil {
			return fmt.Errorf("writing report: %w", err)
		}
	}

	// If the context is cancelled, it's not useful to print everything, just summarize the count.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("failed to build %d packages: %w", len(errs), err)
	}

	return errors.Join(errs...)
}

func buildAll(ctx context.Context, cfg *global, args []string) error {
	var eg errgroup.Group

	var stuff *configStuff
	eg.Go(func() error {
		var err error
		stuff, err = walkConfigs(ctx, cfg)
		return err
	})

	var mu sync.Mutex
	cfg.exists = map[string]map[string]struct{}{}

	for _, arch := range cfg.archs {
		arch := arch

		eg.Go(func() error {
			// Logs will go here to mimic the wolfi Makefile.
			archDir := cfg.logdir(arch)
			if err := os.MkdirAll(archDir, os.ModePerm); err != nil {
				return fmt.Errorf("creating buildlogs directory: %w", err)
			}

			return nil
		})

		// If --destination-repository is set, we want to fetch and parse the APKINDEX concurrently with walking all the configs.
		eg.Go(func() error {
			exist, err := fetchIndex(ctx, cfg.dst, arch)
			if err != nil {
				return err
			}

			mu.Lock()
			defer mu.Unlock()

			cfg.exists[types.ParseArchitecture(arch).ToAPK()] = exist

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return err
	}

	newTask := func(pkg string) *task {
		// We should only hit these errors if dag.NewPackages is wrong.
		loadedCfg := stuff.pkgs.Config(pkg, true)
		if len(loadedCfg) == 0 {
			panic(fmt.Sprintf("package does not seem to exist: %s", pkg))
		}
		c := loadedCfg[0]
		if pkg != c.Package.Name {
			panic(fmt.Sprintf("mismatched package, got %q, want %q", c.Package.Name, pkg))
		}

		return &task{
			cfg:    cfg,
			pkg:    pkg,
			ver:    c.Package.Version,
			epoch:  c.Package.Epoch,
			config: c,
			archs:  filterArchs(cfg.archs, c.Package.TargetArchitecture),
			cond:   sync.NewCond(&sync.Mutex{}),
			deps:   map[string]*task{},
		}
	}

	tasks := map[string]*task{}
	for _, pkg := range stuff.g.Packages() {
		if tasks[pkg] == nil {
			tasks[pkg] = newTask(pkg)
		}
		for k, v := range stuff.m {
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

	todos := tasks
	if len(args) != 0 {
		todos = make(map[string]*task, len(args))

		for _, arg := range args {
			t, ok := tasks[arg]
			if !ok {
				return fmt.Errorf("constraint %q does not exist", arg)
			}
			todos[arg] = t
		}
	}

	for _, t := range todos {
		t.maybeStart(ctx)
	}
	count := len(todos)

	// We're ok with Info level from here on.
	log := clog.FromContext(ctx)

	errs := []error{}
	skipped := 0

	for len(todos) != 0 {
		t := <-cfg.donech
		delete(todos, t.pkg)

		if err := t.err; err != nil {
			errs = append(errs, fmt.Errorf("failed to build %s: %w", t.pkg, err))
			log.Errorf("Failed to build %s (%d/%d)", t.pkg, len(errs), count)
			continue
		}

		// Logging every skipped package is too noisy, so we just print a summary
		// of the number of packages we skipped between actual builds.
		if t.skipped {
			skipped++
			continue
		} else if skipped != 0 {
			log.Infof("Skipped building %d packages", skipped)
			skipped = 0
		}

		log.Infof("Finished building %s (%d/%d)", t.pkg, count-(len(todos)+len(errs)), count)
	}

	if skipped != 0 {
		log.Infof("Skipped building %d packages", skipped)
	}

	// If the context is cancelled, it's not useful to print everything, just summarize the count.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("failed to build %d packages: %w", len(errs), err)
	}

	return errors.Join(errs...)
}

type global struct {
	dryrun bool

	jobch  chan struct{}
	donech chan *task

	dir         string
	dst         string
	pipelineDir string
	runner      string

	archs      []string
	extraKeys  []string
	extraRepos []string

	generateIndex bool

	signingKey  string
	namespace   string
	cacheSource string
	cacheDir    string
	outDir      string

	summary string

	fuses []string

	// arch -> foo.apk -> exists in APKINDEX
	exists map[string]map[string]struct{}

	mu sync.Mutex

	bundle string

	// per arch rate limiter (for APKINDEX)
	writeLimiters map[string]*rate.Limiter
	generations   map[string]int64

	gcs           *storage.Client
	stagingBucket string
	dstBucket     string

	k8sNamespace   string
	serviceAccount string
	machineFamily  string
}

func (g *global) logdir(arch string) string {
	return filepath.Join(g.outDir, arch, "buildlogs")
}

// wrapper around the writeLimiter so this is accounted for in traces
func (g *global) wait(ctx context.Context, arch string) error {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, "wait")
	defer span.End()

	return g.writeLimiters[arch].Wait(ctx)
}

type task struct {
	cfg *global

	pkg    string
	ver    string
	epoch  uint64
	config *dag.Configuration

	bundle *bundle.Task
	archs  []string

	err  error
	deps map[string]*task

	cond    *sync.Cond
	started bool
	done    bool
	skipped bool

	mupods sync.Mutex
	pods   []string

	// How long the actual builds took, including pod scheduling.
	duration time.Duration

	// TODO: This is a hack, refactor the task execution out from the graph walking.
	ref  *name.Digest
	bcfg *bundleConfig
}

func (t *task) gitSDE(ctx context.Context) (time.Time, error) {
	cmd := exec.CommandContext(ctx, "git", "log", "-1", "--pretty=%ct", "--follow", t.config.Path) // #nosec G204
	b, err := cmd.Output()
	if err != nil {
		return time.Time{}, err
	}

	sde, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return time.Time{}, err
	}

	return time.Unix(sde, 0), nil
}

func (t *task) start(ctx context.Context) {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, "start "+t.pkg)
	defer span.End()

	defer func() {
		// When we finish, wake up any goroutines that are waiting on us.
		t.cond.L.Lock()
		t.done = true
		t.cond.Broadcast()
		t.cond.L.Unlock()
		t.cfg.donech <- t
	}()

	for _, dep := range t.deps {
		dep.maybeStart(ctx)
	}

	if len(t.deps) != 0 {
		clog.FromContext(ctx).Debugf("task %q waiting on %q", t.pkg, maps.Keys(t.deps))
	}

	for _, dep := range t.deps {
		if err := dep.wait(ctx); err != nil {
			t.err = fmt.Errorf("waiting on %s: %w", dep.pkg, err)
			return
		}
	}

	// Block on jobch, to limit concurrency. Remove from jobch when done.
	t.cfg.jobch <- struct{}{}
	defer func() { <-t.cfg.jobch }()

	// all deps are done and we're clear to launch.
	if t.ref != nil {
		t.err = t.buildBundle(ctx)
	} else {
		t.err = t.build(ctx)
	}
}

// return intersection of global archs flag and explicit target architectures
func filterArchs(archs, targets []string) []string {
	cloned := slices.Clone(archs)

	if len(targets) == 0 || targets[0] == "all" {
		return cloned
	}

	filtered := slices.DeleteFunc(cloned, func(arch string) bool {
		for _, want := range targets {
			if types.ParseArchitecture(arch) == types.ParseArchitecture(want) {
				return false
			}
		}

		return true
	})

	return filtered
}

func (t *task) pkgver() string {
	return fmt.Sprintf("%s-%s-r%d", t.pkg, t.ver, t.epoch)
}

func (t *task) buildArch(ctx context.Context, arch string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	log := clog.FromContext(ctx)
	logDir := t.cfg.logdir(arch)
	logfile := filepath.Join(logDir, t.pkgver()) + ".log"

	f, err := os.Create(logfile)
	if err != nil {
		return fmt.Errorf("creating logfile: %w", err)
	}
	defer f.Close()

	flog := clog.New(slog.NewTextHandler(f, nil)).With("pkg", t.pkg)
	fctx := clog.WithLogger(ctx, flog)

	sdir := filepath.Join(t.cfg.dir, t.pkg)
	if _, err := os.Stat(sdir); os.IsNotExist(err) {
		if err := os.MkdirAll(sdir, os.ModePerm); err != nil {
			return fmt.Errorf("creating source directory %s: %v", sdir, err)
		}
	} else if err != nil {
		return fmt.Errorf("creating source directory: %v", err)
	}

	runner, err := newRunner(fctx, t.cfg.runner)
	if err != nil {
		return fmt.Errorf("creating runner: %w", err)
	}

	sde, err := t.gitSDE(ctx)
	if err != nil {
		return fmt.Errorf("finding source date epoch: %w", err)
	}

	log.Infof("Building %s", t.pkg)
	bc, err := build.New(fctx,
		build.WithArch(types.ParseArchitecture(arch)),
		build.WithConfig(t.config.Path),
		build.WithPipelineDir(t.cfg.pipelineDir),
		build.WithExtraKeys(t.cfg.extraKeys),
		build.WithExtraRepos(t.cfg.extraRepos),
		build.WithSigningKey(t.cfg.signingKey),
		build.WithRunner(runner),
		build.WithEnvFile(filepath.Join(t.cfg.dir, envFile(arch))),
		build.WithNamespace(t.cfg.namespace),
		build.WithSourceDir(sdir),
		build.WithCacheSource(t.cfg.cacheSource),
		build.WithCacheDir(t.cfg.cacheDir),
		build.WithOutDir(t.cfg.outDir),
		build.WithBuildDate(sde.Format(time.RFC3339)),
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
			log.Errorf("Closing build %q: %v", t.pkg, err)
		}
	}()

	fctx, span := otel.Tracer("wolfictl").Start(fctx, t.pkg)
	defer span.End()
	if err := bc.BuildPackage(fctx); err != nil {
		// We want the error included in the log file.
		flog.Errorf("building package: %v", err)

		// We don't want interleaved logs.
		t.cfg.mu.Lock()
		defer t.cfg.mu.Unlock()

		if err := logs(logfile); err != nil {
			log.Errorf("failed to read logs %q: %v", logfile, err)
		}

		return fmt.Errorf("building package (see %q for logs): %w", logfile, err)
	}

	return nil
}

func (t *task) signedURL(object string) (string, error) {
	bucket := t.cfg.gcs.Bucket(t.cfg.stagingBucket)
	opts := &storage.SignedURLOptions{
		Method:      "PUT",
		Expires:     time.Now().Add(12 * time.Hour),
		ContentType: "application/octet-stream",
	}
	return bucket.SignedURL(object, opts)
}

func (t *task) buildBundleArch(ctx context.Context, arch string) (*bundleResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	ctx, span := otel.Tracer("wolfictl").Start(ctx, arch)
	defer span.End()

	log := clog.FromContext(ctx)

	pod, err := bundle.Podspec(*t.bundle, t.ref, arch, t.cfg.machineFamily, t.cfg.serviceAccount, t.cfg.k8sNamespace)
	if err != nil {
		return nil, fmt.Errorf("creating podspec for %s: %w", t.pkg, err)
	}

	object := fmt.Sprintf("%s/%d-%s-%s-r%d.tar.gz", arch, time.Now().UnixNano(), t.pkg, t.ver, t.epoch)

	log.Debugf("created signed URL for %s", object)
	u, err := t.signedURL(object)
	if err != nil {
		return nil, err
	}

	pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, corev1.EnvVar{
		Name:  "PACKAGES_UPLOAD_URL",
		Value: u,
	})

	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	log.Infof("creating pod for %s", t.pkgver())
	pod, err = clientset.CoreV1().Pods(t.cfg.k8sNamespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("creating pod: %w", err)
	}

	// Needed for report output.
	t.mupods.Lock()
	t.pods = append(t.pods, pod.ObjectMeta.Name)
	t.mupods.Unlock()

	lastPhase := corev1.PodUnknown

	dctx, cancel := context.WithDeadline(ctx, time.Now().Add(6*time.Hour))
	defer cancel()
	if err := wait.PollUntilContextCancel(dctx, 5*time.Second, true, wait.ConditionWithContextFunc(func(ctx context.Context) (bool, error) {
		pod, err = clientset.CoreV1().Pods(t.cfg.k8sNamespace).Get(ctx, pod.ObjectMeta.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		// Only log when stuff actually changes.
		if pod.Status.Phase != lastPhase {
			log.Infof("pod %s phase changed: %s -> %s", pod.ObjectMeta.Name, lastPhase, pod.Status.Phase)
		}
		lastPhase = pod.Status.Phase

		switch pod.Status.Phase {
		case corev1.PodSucceeded:
			if pod.Status.ContainerStatuses[0].State.Terminated == nil {
				return false, nil
			}
			return true, nil
		case corev1.PodFailed:
			return false, fmt.Errorf("pod failed: %s", pod.Status.Message)
		}
		return false, nil
	})); err != nil {
		return nil, fmt.Errorf("waiting for pod: %w", err)
	}

	want := strings.TrimSpace(pod.Status.ContainerStatuses[0].State.Terminated.Message)

	log.Debugf("want hash: %s", want)

	return &bundleResult{
		object: object,
		hash:   want,
	}, nil
}

func (t *task) build(ctx context.Context) error {
	log := clog.FromContext(ctx)

	needsBuild := map[string]bool{}
	needsIndex := map[string]bool{}

	for _, arch := range t.archs {
		apkFile := t.pkgver() + ".apk"
		apkPath := filepath.Join(t.cfg.outDir, arch, apkFile)

		// See if we already have the package indexed.
		if _, ok := t.cfg.exists[arch][apkFile]; ok {
			log.Debugf("Skipping %s, already indexed", apkFile)
			continue
		}

		needsIndex[arch] = true

		// See if we already have the package built.
		_, err := os.Stat(apkPath)
		if err == nil {
			log.Debugf("Skipping %s, already built", apkPath)
			continue
		}

		log.Infof("Checking if %q already exists: %v", apkPath, err)

		needsBuild[arch] = true
	}

	if len(needsBuild) == 0 && len(needsIndex) == 0 {
		t.skipped = true
		return nil
	}

	var buildGroup errgroup.Group
	for arch, need := range needsBuild {
		if !need {
			continue
		}

		arch := types.ParseArchitecture(arch).ToAPK()
		buildGroup.Go(func() error {
			return t.buildArch(ctx, arch)
		})
	}

	if err := buildGroup.Wait(); err != nil {
		return err
	}

	if t.cfg.dryrun {
		return nil
	}

	if !t.cfg.generateIndex {
		return nil
	}

	t.cfg.mu.Lock()
	defer t.cfg.mu.Unlock()

	var indexGroup errgroup.Group
	for arch, need := range needsIndex {
		if !need {
			continue
		}

		arch := types.ParseArchitecture(arch).ToAPK()
		indexGroup.Go(func() error {
			packageDir := filepath.Join(t.cfg.outDir, arch)
			log.Infof("Generating apk index from packages in %s", packageDir)

			cfg := t.config.Configuration
			apkFile := t.pkgver() + ".apk"
			apkPath := filepath.Join(t.cfg.outDir, arch, apkFile)

			var apkFiles []string
			apkFiles = append(apkFiles, apkPath)

			for i := range cfg.Subpackages {
				// gocritic complains about copying if you do the normal thing because Subpackages is not a slice of pointers.
				subName := cfg.Subpackages[i].Name

				subpkgApk := fmt.Sprintf("%s-%s-r%d.apk", subName, cfg.Package.Version, cfg.Package.Epoch)
				subpkgFileName := filepath.Join(packageDir, subpkgApk)
				if _, err := os.Stat(subpkgFileName); err != nil {
					log.Warnf("Skipping subpackage %s (was not built): %v", subpkgFileName, err)
					continue
				}
				apkFiles = append(apkFiles, subpkgFileName)
			}

			opts := []index.Option{
				index.WithPackageFiles(apkFiles),
				index.WithSigningKey(t.cfg.signingKey),
				index.WithMergeIndexFileFlag(true),
				index.WithIndexFile(filepath.Join(packageDir, "APKINDEX.tar.gz")),
			}

			idx, err := index.New(opts...)
			if err != nil {
				return fmt.Errorf("unable to create index: %w", err)
			}

			if err := idx.GenerateIndex(ctx); err != nil {
				return fmt.Errorf("unable to generate index: %w", err)
			}

			return nil
		})
	}

	if err := indexGroup.Wait(); err != nil {
		return err
	}

	// TODO: This is where we would update the index.

	return nil
}

type bundleResult struct {
	object string
	hash   string
}

func (t *task) buildBundle(ctx context.Context) error {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, "build "+t.pkg)
	defer span.End()

	log := clog.FromContext(ctx)

	needsBuild := map[string]bool{}
	needsIndex := map[string]bool{}

	for _, arch := range t.archs {
		apkFile := t.pkgver() + ".apk"
		apkPath := filepath.Join(arch, apkFile)

		// See if we already have the package indexed.
		if _, ok := t.cfg.exists[arch][apkFile]; ok {
			log.Debugf("Skipping %s, already indexed", apkFile)
			continue
		}

		needsIndex[arch] = true

		if t.cfg.dstBucket != "" {
			bucket, dir, ok := strings.Cut(t.cfg.dstBucket, "/")
			if ok {
				apkPath = path.Join(dir, apkPath)
			}

			// See if we already have the package built.
			if _, err := t.cfg.gcs.Bucket(bucket).Object(apkPath).Attrs(ctx); err == nil {
				log.Debugf("Skipping %s, already built", apkPath)
				continue
			}
		}

		needsBuild[arch] = true
	}

	if len(needsBuild) == 0 && len(needsIndex) == 0 {
		t.skipped = true
		return nil
	}

	var (
		buildGroup errgroup.Group
	)

	var mu sync.Mutex
	results := map[string]*bundleResult{}

	start := time.Now()
	for arch, need := range needsBuild {
		if !need {
			continue
		}

		arch := types.ParseArchitecture(arch).ToAPK()
		buildGroup.Go(func() error {
			res, err := t.buildBundleArch(ctx, arch)
			if err != nil {
				return err
			}

			mu.Lock()
			defer mu.Unlock()

			results[arch] = res

			return nil
		})
	}

	err := buildGroup.Wait()
	t.duration = time.Since(start)
	if err != nil {
		return err
	}

	if len(needsBuild) != 0 {
		log.Infof("Pods finished: %s", t.pkg)
	}

	if t.cfg.dryrun {
		return nil
	}

	if !t.cfg.generateIndex {
		return nil
	}

	log.Infof("Processing results: %s", t.pkg)

	tmpdir, err := os.MkdirTemp("", "")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpdir)

	var filemu sync.Mutex
	filesByArch := map[string][]string{}

	var pkgGroup errgroup.Group
	for arch, need := range needsIndex {
		if !need {
			continue
		}

		arch := types.ParseArchitecture(arch).ToAPK()
		pkgGroup.Go(func() error {
			files, err := t.uploadBundle(ctx, arch, results, tmpdir)
			if err != nil {
				return err
			}

			filemu.Lock()
			defer filemu.Unlock()

			filesByArch[arch] = files

			return nil
		})
	}

	if err := pkgGroup.Wait(); err != nil {
		return fmt.Errorf("uploading bundles: %w", err)
	}

	t.cfg.mu.Lock()
	defer t.cfg.mu.Unlock()

	var indexGroup errgroup.Group
	for arch, need := range needsIndex {
		if !need {
			continue
		}

		arch := types.ParseArchitecture(arch).ToAPK()
		indexGroup.Go(func() error {
			return t.indexBundle(ctx, arch, filesByArch[arch])
		})
	}

	if err := indexGroup.Wait(); err != nil {
		return fmt.Errorf("failed to regenerate index: %w", err)
	}

	if t.cfg.dstBucket == "" {
		clog.FromContext(ctx).Warnf("Skipping uploading indexes because --destination-bucket is not set")
		return nil
	}

	log.Infof("Uploading APKINDEX: %s", t.pkg)

	// We do this after indexGroup because we only want to upload them if all archs succeeded.
	var uploadGroup errgroup.Group
	for arch, need := range needsIndex {
		if !need {
			continue
		}

		arch := types.ParseArchitecture(arch).ToAPK()
		uploadGroup.Go(func() error {
			return t.uploadIndex(ctx, arch)
		})
	}

	if err := uploadGroup.Wait(); err != nil {
		return fmt.Errorf("uploading indexes: %w", err)
	}

	return nil
}

func (t *task) uploadBundle(ctx context.Context, arch string, results map[string]*bundleResult, tmpdir string) ([]string, error) {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, "indexBundle")
	defer span.End()

	log := clog.FromContext(ctx)

	packageDir := filepath.Join(tmpdir, arch)
	if err := os.MkdirAll(packageDir, os.ModePerm); err != nil {
		return nil, err
	}

	apkFiles := make([]string, 0, len(t.bundle.Subpackages)+1)

	apkFile := t.pkgver() + ".apk"
	apkPath := filepath.Join(packageDir, apkFile)

	res, ok := results[arch]
	if ok {
		if err := t.fetchResult(ctx, res, tmpdir); err != nil {
			return nil, fmt.Errorf("fetching bundle output: %w", err)
		}

		for _, subName := range t.bundle.Subpackages {
			subpkgApk := fmt.Sprintf("%s-%s-r%d.apk", subName, t.ver, t.epoch)
			subpkgFileName := filepath.Join(packageDir, subpkgApk)
			if _, err := os.Stat(subpkgFileName); err != nil {
				log.Warnf("Skipping subpackage %s (was not built): %v", subpkgFileName, err)
				continue
			}

			log.Debugf("re-signing %s", subpkgApk)
			if err := sign.APK(ctx, subpkgFileName, t.cfg.signingKey); err != nil {
				return nil, fmt.Errorf("signing %s: %w", subpkgApk, err)
			}

			apkFiles = append(apkFiles, subpkgFileName)
		}

		// Note that the primary APK here is intentionally last.
		// When we check if a package has already been uploaded (needsBuild above), we use this file.
		// It's important that we upload it last so that we know all the other APKs were also uploaded.
		log.Debugf("re-signing %s", apkFile)
		if err := sign.APK(ctx, apkPath, t.cfg.signingKey); err != nil {
			return nil, fmt.Errorf("signing %s: %w", apkFile, err)
		}

		apkFiles = append(apkFiles, apkPath)

		if err := t.uploadAPKs(ctx, arch, apkFiles); err != nil {
			return nil, err
		}
	} else {
		for _, subName := range t.bundle.Subpackages {
			subpkgApk := fmt.Sprintf("%s-%s-r%d.apk", subName, t.ver, t.epoch)
			subpkgFileName := filepath.Join(packageDir, subpkgApk)

			if err := t.downloadAPK(ctx, arch, packageDir, subpkgApk); err != nil {
				if errors.Is(err, storage.ErrObjectNotExist) {
					log.Warnf("Skipping subpackage %s (was not built): %v", subpkgApk, err)
					continue
				}
				return nil, err
			}

			apkFiles = append(apkFiles, subpkgFileName)
		}

		if err := t.downloadAPK(ctx, arch, packageDir, apkFile); err != nil {
			return nil, err
		}

		apkFiles = append(apkFiles, apkPath)
	}

	return apkFiles, nil
}

func (t *task) indexBundle(ctx context.Context, arch string, apkFiles []string) error {
	opts := []index.Option{
		index.WithPackageFiles(apkFiles),
		index.WithSigningKey(t.cfg.signingKey),
		index.WithMergeIndexFileFlag(true),
		index.WithIndexFile(filepath.Join(t.cfg.outDir, arch, "APKINDEX.tar.gz")),
	}

	idx, err := index.New(opts...)
	if err != nil {
		return fmt.Errorf("unable to create index: %w", err)
	}

	// GenerateIndex is a little too chatty for my liking, so only log warnings and up.
	quiet := clog.New(charmlog.NewWithOptions(os.Stderr, charmlog.Options{ReportTimestamp: true, Level: charmlog.WarnLevel}))
	qctx := clog.WithLogger(ctx, quiet)

	if err := idx.GenerateIndex(qctx); err != nil {
		return fmt.Errorf("unable to generate index: %w", err)
	}

	return nil
}

func (t *task) downloadAPK(ctx context.Context, arch, pkgdir, apkfile string) error {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, "downloadAPK")
	defer span.End()

	log := clog.FromContext(ctx)

	obj := path.Join(arch, apkfile)
	bucket, dir, ok := strings.Cut(t.cfg.dstBucket, "/")
	if ok {
		obj = path.Join(dir, obj)
	}

	log.Debugf("Downloading previously uploaded %s", obj)

	rc, err := t.cfg.gcs.Bucket(bucket).Object(obj).NewReader(ctx)
	if err != nil {
		return err
	}
	defer rc.Close()

	f, err := os.Create(filepath.Join(pkgdir, apkfile))
	if err != nil {
		return err
	}

	if _, err := io.Copy(f, rc); err != nil {
		return err
	}

	if err := f.Close(); err != nil {
		return err
	}

	return nil
}

func (t *task) fetchResult(ctx context.Context, res *bundleResult, tmpdir string) error {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, "fetchResult")
	defer span.End()

	log := clog.FromContext(ctx)

	log.Debugf("fetching object %s", res.object)
	rc, err := t.cfg.gcs.Bucket(t.cfg.stagingBucket).Object(res.object).NewReader(ctx)
	if err != nil {
		return err
	}
	defer rc.Close()

	tmp, err := os.CreateTemp("", "")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	h := sha256.New()
	mw := io.MultiWriter(tmp, h)

	log.Debugf("downloading %s to %s", res.object, tmp.Name())
	if _, err := io.Copy(mw, rc); err != nil {
		return err
	}

	got := hex.EncodeToString(h.Sum(nil))
	if got != res.hash {
		return fmt.Errorf("hashing %s got != want; %q != %q", res.object, got, res.hash)
	}

	log.Debugf("hashes matched %s", res.hash)

	// Seek to the start so we can untar it.
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}

	log.Debugf("untarring %s", tmp.Name())
	if err := tar.Untar(tmp, tmpdir); err != nil {
		return fmt.Errorf("untarring %s: %w", tmp.Name(), err)
	}

	return nil
}

func (t *task) uploadAPKs(ctx context.Context, arch string, apkFiles []string) error {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, "uploadAPKs")
	defer span.End()

	if t.cfg.dstBucket == "" {
		clog.FromContext(ctx).Warnf("Skipping uploading packages because --destination-bucket is not set")
		return nil
	}

	for _, apkFile := range apkFiles {
		base := path.Base(apkFile)
		obj := path.Join(arch, base)

		bucket, dir, ok := strings.Cut(t.cfg.dstBucket, "/")
		if ok {
			obj = path.Join(dir, obj)
		}

		f, err := os.Open(apkFile)
		if err != nil {
			return err
		}
		defer f.Close()

		// The gcs client will only retry wc.Close() errors if the upload is idempotent.
		// Using this DoesNotExist condition causes the upload to be idempotent.
		// This is fine because these objects should only ever be written once.
		cond := storage.Conditions{DoesNotExist: true}

		wc := t.cfg.gcs.Bucket(bucket).Object(obj).If(cond).NewWriter(ctx)

		if _, err := io.Copy(wc, f); err != nil {
			return fmt.Errorf("uploading %s: %w", obj, err)
		}

		if err := wc.Close(); err != nil {
			return fmt.Errorf("finalizing uploading of %s: %w", obj, err)
		}
	}

	return nil
}

func (t *task) uploadIndex(ctx context.Context, arch string) error {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, "uploadIndex")
	defer span.End()

	filename := filepath.Join(t.cfg.outDir, arch, "APKINDEX.tar.gz")

	f, err := os.Open(filename)
	if err != nil {
		return err
	}

	obj := path.Join(arch, "APKINDEX.tar.gz")
	bucket, dir, ok := strings.Cut(t.cfg.dstBucket, "/")
	if ok {
		obj = path.Join(dir, obj)
	}

	if err := t.cfg.wait(ctx, arch); err != nil {
		return fmt.Errorf("waiting for rate limit: %w", err)
	}

	// The gcs client will only retry wc.Close() errors if the upload is idempotent.
	// Using this GenerationMatch condition causes the upload to be idempotent.
	// We expect to be the only writer of these objects, so this is fine.
	// If we allow multiple concurrent index uploaders, we can also use this to safely retry.
	cond := storage.Conditions{GenerationMatch: t.cfg.generations[arch]}
	if cond.GenerationMatch == 0 {
		// This fails with "NewWriter: empty conditions" if generation is 0,
		// so set DoesNotExist instead.
		cond.DoesNotExist = true
	}

	wc := t.cfg.gcs.Bucket(bucket).Object(obj).If(cond).NewWriter(ctx)

	if _, err := io.Copy(wc, f); err != nil {
		return fmt.Errorf("uploading %s: %w", obj, err)
	}

	if err := wc.Close(); err != nil {
		return fmt.Errorf("finalizing upload of %s: %w", obj, err)
	}

	// Update this arch's generation so we can use it for idempotency above.
	t.cfg.generations[arch] = wc.Attrs().Generation

	return nil
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
func (t *task) wait(ctx context.Context) error {
	_, span := otel.Tracer("wolfictl").Start(ctx, "waiting on "+t.pkg)
	defer span.End()

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

func logs(fname string) error {
	fmt.Printf("::group::%s\n", fname)
	f, err := os.Open(fname)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(os.Stdout, f); err != nil {
		return err
	}
	fmt.Printf("::endgroup::\n")
	return nil
}

// TODO: I think this is probably wrong, actually.
func (t *task) sourceDir() (string, error) {
	sdir := filepath.Join(t.cfg.dir, t.pkg)
	if _, err := os.Stat(sdir); os.IsNotExist(err) {
		if err := os.MkdirAll(sdir, os.ModePerm); err != nil {
			return "", fmt.Errorf("creating source directory %s: %v", sdir, err)
		}
	} else if err != nil {
		return "", fmt.Errorf("creating source directory: %v", err)
	}

	return sdir, nil
}
