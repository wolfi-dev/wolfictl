package cli

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
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
	"chainguard.dev/apko/pkg/apk/auth"
	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/container"
	"chainguard.dev/melange/pkg/container/docker"
	"chainguard.dev/melange/pkg/index"
	"cloud.google.com/go/storage"
	charmlog "github.com/charmbracelet/log"
	"github.com/dominikbraun/graph"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/trace"
	"golang.org/x/exp/maps"
	"golang.org/x/oauth2/google"
	"golang.org/x/sync/errgroup"
	gcontainer "google.golang.org/api/container/v1"
	"google.golang.org/api/option"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"

	"github.com/chainguard-dev/clog"
	"github.com/wolfi-dev/wolfictl/pkg/dag"
	"github.com/wolfi-dev/wolfictl/pkg/private/bundle"
	"github.com/wolfi-dev/wolfictl/pkg/tar"
)

func cmdBuild() *cobra.Command {
	var traceFile string
	var anns []string // string list annotations

	cfg := Global{
		BuildID: uuid.New(),
	}

	// TODO: buildworld bool (build deps vs get them from package repo)
	// TODO: builddownstream bool (build things that depend on listed packages)
	cmd := &cobra.Command{
		Use:           "build",
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			cfg.Annotations = map[string]string{}
			for _, ann := range anns {
				k, v, ok := strings.Cut(ann, "=")
				if !ok {
					return fmt.Errorf("invalid annotation: %q", ann)
				}
				cfg.Annotations[k] = v
			}

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

			if cfg.Jobs == 0 {
				cfg.Jobs = runtime.GOMAXPROCS(0)
			}
			cfg.jobch = make(chan struct{}, cfg.Jobs)
			cfg.donech = make(chan *task, cfg.Jobs)

			if cfg.signingKey == "" {
				cfg.signingKey = filepath.Join(cfg.Dir, "local-melange.rsa")
			}
			if cfg.PipelineDir == "" {
				cfg.PipelineDir = filepath.Join(cfg.Dir, "pipelines")
			}
			if cfg.OutDir == "" {
				cfg.OutDir = filepath.Join(cfg.Dir, "packages")
			}

			if cfg.Bundle != "" {
				if cfg.StagingBucket == "" {
					return fmt.Errorf("need --bucket with --bundle")
				}

				client, err := storage.NewClient(ctx, option.WithTelemetryDisabled())
				if err != nil {
					return fmt.Errorf("creating gcs client: %w", err)
				}
				cfg.GCS = client

				return BuildBundles(ctx, &cfg)
			}

			return buildAll(ctx, &cfg, args)
		},
	}

	cmd.Flags().StringVarP(&cfg.Dir, "dir", "d", ".", "directory to search for melange configs")
	cmd.Flags().StringVar(&cfg.PipelineDir, "pipeline-dir", "", "directory used to extend defined built-in pipelines")
	cmd.Flags().StringVar(&cfg.Runner, "runner", "docker", "which runner to use to enable running commands, default is based on your platform.")
	cmd.Flags().StringSliceVar(&cfg.Archs, "arch", []string{"x86_64", "aarch64"}, "arch of package to build")
	cmd.Flags().BoolVar(&cfg.dryrun, "dry-run", false, "print commands instead of executing them")
	cmd.Flags().StringSliceVarP(&cfg.ExtraKeys, "keyring-append", "k", []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"}, "path to extra keys to include in the build environment keyring")
	cmd.Flags().StringSliceVarP(&cfg.ExtraRepos, "repository-append", "r", []string{"https://packages.wolfi.dev/os"}, "path to extra repositories to include in the build environment")
	cmd.Flags().StringVar(&cfg.signingKey, "signing-key", "", "key to use for signing")
	cmd.Flags().StringVar(&cfg.PurlNamespace, "namespace", "wolfi", "namespace to use in package URLs in SBOM (eg wolfi, alpine)")
	cmd.Flags().StringVar(&cfg.OutDir, "out-dir", "", "directory where packages will be output")
	cmd.Flags().StringVar(&cfg.summary, "summary", "", "file to write build summary")
	cmd.Flags().StringVar(&cfg.cacheDir, "cache-dir", "./melange-cache/", "directory used for cached inputs")
	cmd.Flags().StringVar(&cfg.cacheSource, "cache-source", "", "directory or bucket used for preloading the cache")
	cmd.Flags().BoolVar(&cfg.generateIndex, "generate-index", true, "whether to generate APKINDEX.tar.gz")
	cmd.Flags().StringVar(&cfg.DestinationRepo, "destination-repository", "", "repo used to check for (and skip) existing packages")
	cmd.Flags().StringVar(&cfg.UploadRepo, "upload-repository", "", "repo where packages will be uploaded")
	cmd.Flags().BoolVar(&cfg.Dedupe, "dedupe", false, "attempt (best effort) to avoid multiple build pods per APK")
	cmd.Flags().StringVar(&cfg.Bundle, "bundle", "", "bundle of work to do (experimental)")
	cmd.Flags().StringVar(&cfg.StagingBucket, "bucket", "", "gcs bucket to upload results (experimental)")

	cmd.Flags().IntVarP(&cfg.Jobs, "jobs", "j", 0, "number of jobs to run concurrently (default is GOMAXPROCS)")
	cmd.Flags().StringVar(&traceFile, "trace", "", "where to write trace output")

	cmd.Flags().StringVar(&cfg.K8sNamespace, "k8s-namespace", "default", "namespace to deploy pods into for builds.")
	cmd.Flags().StringVar(&cfg.MachineFamily, "machine-family", "", "machine family for amd64 builds")
	cmd.Flags().StringVar(&cfg.ServiceAccount, "service-account", "default", "service-account to run pods as.")
	cmd.Flags().StringSliceVarP(&anns, "annotations", "a", []string{}, "key=value pairs to add to the pod spec annotations. The keys will be prefixed with 'melange.chainguard.dev/' on the pod.")

	return cmd
}

type configStuff struct {
	g    *dag.Graph
	m    map[string]map[string]graph.Edge[string]
	pkgs *dag.Packages
}

func walkConfigs(ctx context.Context, cfg *Global) (*configStuff, error) {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, "walkConfigs")
	defer span.End()

	// We want to ignore info level here during setup, but further down below we pull whatever was passed to use via ctx.
	log := clog.New(charmlog.NewWithOptions(os.Stderr, charmlog.Options{ReportTimestamp: true, Level: charmlog.WarnLevel}))
	ctx = clog.WithLogger(ctx, log)

	// Walk all the melange configs in cfg.Dir, parses them, and builds the dependency graph of environment + pipelines (build time deps).
	pkgs, err := dag.NewPackages(ctx, os.DirFS(cfg.Dir), cfg.Dir, cfg.PipelineDir)
	if err != nil {
		return nil, err
	}

	g, err := dag.NewGraph(ctx, pkgs, dag.WithKeys(cfg.ExtraKeys...), dag.WithRepos(cfg.ExtraRepos...))
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

func fetchIndex(ctx context.Context, dst, arch string) (map[string]struct{}, error) {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, "fetchIndex")
	defer span.End()

	exist := map[string]struct{}{}
	if dst == "" {
		return exist, nil
	}

	repo := apk.Repository{
		URI: fmt.Sprintf("%s/%s/%s", dst, arch, "APKINDEX.tar.gz"),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, repo.URI, nil)
	if err != nil {
		return nil, err
	}
	if err := auth.DefaultAuthenticators.AddAuth(ctx, req); err != nil {
		return nil, fmt.Errorf("error adding auth: %w", err)
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

func BuildBundles(ctx context.Context, cfg *Global) error {
	log := clog.FromContext(ctx)

	log.Infof("building bundle %s", cfg.BuildID.String())

	var eg errgroup.Group

	bundles, err := bundle.Pull(cfg.Bundle)
	if err != nil {
		return fmt.Errorf("failed to pull bundle: %w", err)
	}

	if cfg.Dir == "" {
		cfg.Dir = "."
	}
	if cfg.OutDir == "" {
		cfg.OutDir = filepath.Join(cfg.Dir, "packages")
	}

	if cfg.Jobs == 0 {
		cfg.Jobs = runtime.GOMAXPROCS(0)
	}
	cfg.jobch = make(chan struct{}, cfg.Jobs)
	cfg.donech = make(chan *task, cfg.Jobs)

	if err := cfg.initK8s(ctx); err != nil {
		return fmt.Errorf("initializing k8s: %w", err)
	}

	var mu sync.Mutex
	cfg.exists = map[string]map[string]struct{}{}

	for _, arch := range cfg.Archs {
		arch := types.ParseArchitecture(arch).ToAPK()

		if err := os.MkdirAll(filepath.Join(cfg.OutDir, arch), os.ModePerm); err != nil {
			return fmt.Errorf("creating arch directory: %w", err)
		}

		// If --destination-repository or --upload-repository is set, we want to fetch and parse the APKINDEXes concurrently with walking all the configs.
		eg.Go(func() error {
			exist, err := fetchIndex(ctx, cfg.DestinationRepo, arch)
			if err != nil {
				return fmt.Errorf("failed to fetch index from destination repo %s for arch %s; %w", cfg.DestinationRepo, arch, err)
			}

			existRepo, err := fetchIndex(ctx, cfg.UploadRepo, arch)
			if err != nil {
				return fmt.Errorf("fetching index from UploadRepo %s for arch %s; %w", cfg.UploadRepo, arch, err)
			}

			for k, v := range existRepo {
				exist[k] = v
			}

			mu.Lock()
			defer mu.Unlock()

			cfg.exists[arch] = exist

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return fmt.Errorf("failed wait: %w", err)
	}

	newTask := func(pkg string, bundle bundle.Task, ref name.Digest) *task {
		return &task{
			cfg:    cfg,
			pkg:    pkg,
			ver:    bundle.Version,
			epoch:  bundle.Epoch,
			bundle: &bundle,
			ref:    &ref,
			archs:  filterArchs(cfg.Archs, bundle.Architectures),
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
			log.Errorf("Failed to build %s (%d/%d): %v", t.pkg, len(errs), count, err)
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
				return fmt.Errorf("creating summary: %w", err)
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

func buildAll(ctx context.Context, cfg *Global, args []string) error {
	var eg errgroup.Group

	var stuff *configStuff
	eg.Go(func() error {
		var err error
		stuff, err = walkConfigs(ctx, cfg)
		if err != nil {
			return fmt.Errorf("walking config: %w", err)
		}
		return nil
	})

	var mu sync.Mutex
	cfg.exists = map[string]map[string]struct{}{}

	for _, arch := range cfg.Archs {
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
			exist, err := fetchIndex(ctx, cfg.DestinationRepo, arch)
			if err != nil {
				return fmt.Errorf("fetching index from destination repo %s for arch %s; %w", cfg.DestinationRepo, arch, err)
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
			archs:  filterArchs(cfg.Archs, c.Package.TargetArchitecture),
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

type Global struct {
	BuildID uuid.UUID

	dryrun bool

	Jobs   int
	jobch  chan struct{}
	donech chan *task

	Dir             string
	DestinationRepo string
	UploadRepo      string
	PipelineDir     string
	Runner          string
	Dedupe          bool

	Archs      []string
	ExtraKeys  []string
	ExtraRepos []string

	generateIndex bool

	signingKey    string
	PurlNamespace string
	cacheSource   string
	cacheDir      string
	OutDir        string

	summary string

	Fuses []string

	// arch -> foo.apk -> exists in APKINDEX
	exists map[string]map[string]struct{}

	mu sync.Mutex

	Bundle string

	GCS           *storage.Client
	StagingBucket string

	clientset *kubernetes.Clientset

	K8sNamespace   string
	ServiceAccount string
	MachineFamily  string
	Annotations    map[string]string

	ProjectID       string
	ClusterLocation string
	ClusterName     string
}

func (g *Global) logdir(arch string) string {
	return filepath.Join(g.OutDir, arch, "buildlogs")
}

type task struct {
	cfg *Global

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
	bcfg *BundleConfig
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
		if err := dep.wait(); err != nil {
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

	log := clog.FromContext(ctx).With("arch", arch)
	logDir := t.cfg.logdir(arch)
	logfile := filepath.Join(logDir, t.pkgver()) + ".log"

	f, err := os.Create(logfile)
	if err != nil {
		return fmt.Errorf("creating logfile: %w", err)
	}
	defer f.Close()

	flog := clog.New(slog.NewTextHandler(f, nil)).With("pkg", t.pkg)
	fctx := clog.WithLogger(ctx, flog)

	sdir := filepath.Join(t.cfg.Dir, t.pkg)
	if _, err := os.Stat(sdir); os.IsNotExist(err) {
		if err := os.MkdirAll(sdir, os.ModePerm); err != nil {
			return fmt.Errorf("creating source directory %s: %v", sdir, err)
		}
	} else if err != nil {
		return fmt.Errorf("creating source directory: %v", err)
	}

	runner, err := newRunner(fctx, t.cfg.Runner)
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
		build.WithPipelineDir(t.cfg.PipelineDir),
		build.WithExtraKeys(t.cfg.ExtraKeys),
		build.WithExtraRepos(t.cfg.ExtraRepos),
		build.WithSigningKey(t.cfg.signingKey),
		build.WithRunner(runner),
		build.WithEnvFile(filepath.Join(t.cfg.Dir, envFile(arch))),
		build.WithNamespace(t.cfg.PurlNamespace),
		build.WithSourceDir(sdir),
		build.WithCacheSource(t.cfg.cacheSource),
		build.WithCacheDir(t.cfg.cacheDir),
		build.WithOutDir(t.cfg.OutDir),
		build.WithBuildDate(sde.Format(time.RFC3339)),
		build.WithRemove(true),
	)
	if err != nil {
		return fmt.Errorf("creating build: %w", err)
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
	bucket := t.cfg.GCS.Bucket(t.cfg.StagingBucket)
	opts := &storage.SignedURLOptions{
		Method:      "PUT",
		Expires:     time.Now().Add(12 * time.Hour),
		ContentType: "application/octet-stream",
	}
	return bucket.SignedURL(object, opts)
}

func (t *task) buildBundleArch(ctx context.Context, arch string) (*bundleResult, error) {
	log := clog.FromContext(ctx).With("arch", arch)

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context error: %w", err)
	}

	ctx, span := otel.Tracer("wolfictl").Start(ctx, arch)
	defer span.End()

	object := fmt.Sprintf("%s/%d-%s-%s-r%d.tar.gz", arch, time.Now().UnixNano(), t.pkg, t.ver, t.epoch)

	var (
		pod       *corev1.Pod
		lastPhase = corev1.PodUnknown
	)

	if t.cfg.Dedupe {
		// See if there is already a pod scheduled for this package.
		goarch := types.ParseArchitecture(arch).String()
		selectors := []string{
			fmt.Sprintf("melange.chainguard.dev/package=%s", t.pkg),
			fmt.Sprintf("melange.chainguard.dev/arch=%s", goarch),
			fmt.Sprintf("melange.chainguard.dev/version=%s-r%d", t.ver, t.epoch),
		}

		pods, err := t.cfg.clientset.CoreV1().Pods(t.cfg.K8sNamespace).List(ctx, metav1.ListOptions{
			LabelSelector: strings.Join(selectors, ","),
		})
		if err != nil {
			return nil, fmt.Errorf("listing pods: %w", err)
		}

		for i := range pods.Items {
			p := &pods.Items[i]
			if p.Status.Phase == corev1.PodFailed {
				continue
			}
			pod = p
			lastPhase = p.Status.Phase

			// Pull out the object so we can adopt this pod.
			object = pod.ObjectMeta.Annotations["melange.chainguard.dev/object"]

			log.Infof("found already %s pod %s for %s", p.Status.Phase, pod.ObjectMeta.Name, t.pkgver())

			break
		}
	}

	if pod == nil {
		var err error
		pod, err = bundle.Podspec(*t.bundle, t.ref, arch, t.cfg.MachineFamily, t.cfg.ServiceAccount, t.cfg.K8sNamespace, t.cfg.Annotations)
		if err != nil {
			return nil, fmt.Errorf("creating podspec for %s: %w", t.pkg, err)
		}

		u, err := t.signedURL(object)
		if err != nil {
			return nil, fmt.Errorf("getting signed url: %w", err)
		}
		log.Debugf("created signed URL for %s", object)

		pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, corev1.EnvVar{
			Name:  "PACKAGES_UPLOAD_URL",
			Value: u,
		})

		// Include the object URL so this pod can be adopted by other runners if necessary.
		pod.ObjectMeta.Annotations["melange.chainguard.dev/object"] = object

		log.Infof("creating pod for %s", t.pkgver())
		pod, err = t.cfg.clientset.CoreV1().Pods(t.cfg.K8sNamespace).Create(ctx, pod, metav1.CreateOptions{})
		if err != nil {
			return nil, fmt.Errorf("creating pod: %w", err)
		}
	}

	// Needed for report output.
	t.mupods.Lock()
	t.pods = append(t.pods, pod.ObjectMeta.Name)
	t.mupods.Unlock()

	dctx, cancel := context.WithDeadline(ctx, time.Now().Add(6*time.Hour))
	defer cancel()
	if err := wait.PollUntilContextCancel(dctx, 5*time.Second, true, wait.ConditionWithContextFunc(func(ctx context.Context) (bool, error) {
		var err error
		pod, err = t.cfg.clientset.CoreV1().Pods(t.cfg.K8sNamespace).Get(ctx, pod.ObjectMeta.Name, metav1.GetOptions{})
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
			log.With("status", pod.Status).Errorf("pod failed")
			msg := "unknown termination message"
			if pod.Status.ContainerStatuses[0].State.Terminated != nil {
				msg = pod.Status.ContainerStatuses[0].State.Terminated.Message
			}
			return false, fmt.Errorf("pod failed: %s", msg)
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
	log := clog.FromContext(ctx).With("pkg", t.pkg, "pkgver", t.pkgver())
	ctx = clog.WithLogger(ctx, log)

	needsBuild := map[string]bool{}
	needsIndex := map[string]bool{}

	for _, arch := range t.archs {
		apkFile := t.pkgver() + ".apk"
		apkPath := filepath.Join(t.cfg.OutDir, arch, apkFile)

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

		log.Debugf("Checking if %q already exists: %v", apkPath, err)

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
			packageDir := filepath.Join(t.cfg.OutDir, arch)
			log.Infof("Generating apk index from packages in %s", packageDir)

			cfg := t.config.Configuration
			apkFile := t.pkgver() + ".apk"
			apkPath := filepath.Join(t.cfg.OutDir, arch, apkFile)

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

	log := clog.FromContext(ctx).With("pkg", t.pkg, "pkgver", t.pkgver())
	ctx = clog.WithLogger(ctx, log)

	needsBuild := map[string]bool{}

	for _, arch := range t.archs {
		apkFile := t.pkgver() + ".apk"

		// See if we already have the package indexed.
		if _, ok := t.cfg.exists[arch][apkFile]; ok {
			log.Debugf("Skipping %s, already indexed", apkFile)
			continue
		}

		needsBuild[arch] = true
	}

	if len(needsBuild) == 0 {
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
		return fmt.Errorf("building group: %w", err)
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

	if t.cfg.UploadRepo == "" {
		clog.FromContext(ctx).Warnf("Skipping uploading packages because --upload-repository is not set")
		return nil
	}

	var pkgGroup errgroup.Group
	for arch, need := range needsBuild {
		if !need {
			continue
		}

		arch := types.ParseArchitecture(arch).ToAPK()
		pkgGroup.Go(func() error {
			if err := t.uploadBundle(ctx, arch, results, tmpdir); err != nil {
				return fmt.Errorf("uploading bundle: %w", err)
			}

			return nil
		})
	}

	if err := pkgGroup.Wait(); err != nil {
		return fmt.Errorf("uploading bundles: %w", err)
	}

	return nil
}

func (t *task) uploadBundle(ctx context.Context, arch string, results map[string]*bundleResult, tmpdir string) error {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, "indexBundle")
	defer span.End()

	log := clog.FromContext(ctx)

	packageDir := filepath.Join(tmpdir, arch)
	if err := os.MkdirAll(packageDir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to mkdir: %s; %w", packageDir, err)
	}

	apkFiles := make([]string, 0, len(t.bundle.Subpackages)+1)

	apkFile := t.pkgver() + ".apk"
	apkPath := filepath.Join(packageDir, apkFile)

	res, ok := results[arch]
	if !ok {
		return nil
	}

	if err := t.fetchResult(ctx, res, tmpdir); err != nil {
		return fmt.Errorf("fetching bundle output: %w", err)
	}

	for _, subName := range t.bundle.Subpackages {
		subpkgApk := fmt.Sprintf("%s-%s-r%d.apk", subName, t.ver, t.epoch)
		subpkgFileName := filepath.Join(packageDir, subpkgApk)
		if _, err := os.Stat(subpkgFileName); err != nil {
			log.Warnf("Skipping subpackage %s (was not built): %v", subpkgFileName, err)
			continue
		}

		apkFiles = append(apkFiles, subpkgFileName)
	}

	// Note that the primary APK here is intentionally last.
	// When we check if a package has already been uploaded (needsBuild above), we use this file.
	// It's important that we upload it last so that we know all the other APKs were also uploaded.
	apkFiles = append(apkFiles, apkPath)

	if err := t.uploadAPKs(ctx, arch, apkFiles); err != nil {
		return fmt.Errorf("uploading apks: %w", err)
	}

	return nil
}

func (t *task) fetchResult(ctx context.Context, res *bundleResult, tmpdir string) error {
	ctx, span := otel.Tracer("wolfictl").Start(ctx, "fetchResult")
	defer span.End()

	log := clog.FromContext(ctx)

	log.Debugf("fetching object %s", res.object)
	rc, err := t.cfg.GCS.Bucket(t.cfg.StagingBucket).Object(res.object).NewReader(ctx)
	if err != nil {
		return fmt.Errorf("fetching %q: %w", res.object, err)
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

	for _, apkFile := range apkFiles {
		base := path.Base(apkFile)
		obj := path.Join(arch, base)

		uploadURL := fmt.Sprintf("%s/%s", t.cfg.UploadRepo, obj)
		u, err := url.Parse(uploadURL)
		if err != nil {
			return fmt.Errorf("parsing %q: %w", uploadURL, err)
		}

		f, err := os.Open(apkFile)
		if err != nil {
			return fmt.Errorf("opening apk: %s; %w", apkFile, err)
		}

		info, err := f.Stat()
		if err != nil {
			return fmt.Errorf("statting %s: %w", apkFile, err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), f)
		if err != nil {
			return fmt.Errorf("creating POST request for %q: %w", u.Redacted(), err)
		}
		req.ContentLength = info.Size()

		if err := auth.DefaultAuthenticators.AddAuth(ctx, req); err != nil {
			return fmt.Errorf("error adding auth: %w", err)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("POST %q: %w", u.Redacted(), err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusAccepted {
			return fmt.Errorf("POST %q: %s", u.Redacted(), resp.Status)
		}
	}

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

// returns the sourceDir _relative_ to the --dir flag
func (t *task) sourceDir() (string, error) {
	sdir := filepath.Join(t.cfg.Dir, t.pkg)
	if _, err := os.Stat(sdir); os.IsNotExist(err) {
		if err := os.MkdirAll(sdir, os.ModePerm); err != nil {
			return "", fmt.Errorf("creating source directory %s: %v", sdir, err)
		}
	} else if err != nil {
		return "", fmt.Errorf("statting source directory: %v", err)
	}

	rel, err := filepath.Rel(t.cfg.Dir, sdir)
	if err != nil {
		return "", err
	}

	return rel, nil
}

func getK8sClusterConfig(ctx context.Context, projectID, clusterLocation, clusterName string) (*api.Config, error) {
	// get a token
	ts, err := google.DefaultTokenSource(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, fmt.Errorf("getting google default token: %w", err)
	}
	tok, err := ts.Token()
	if err != nil {
		return nil, fmt.Errorf("extracting token: %w", err)
	}

	// Call out to google to get cluster information
	svc, err := gcontainer.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("container.NewService: %w", err)
	}

	cName := fmt.Sprintf("projects/%s/locations/%s/clusters/%s", projectID, clusterLocation, clusterName)
	cluster, err := svc.Projects.Locations.Clusters.Get(cName).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("clusters get name=%s: %w", cName, err)
	}

	// Basic config structure
	ret := api.Config{
		APIVersion: "v1",
		Kind:       "Config",
		Clusters:   map[string]*api.Cluster{},  // Clusters is a map of referencable names to cluster configs
		AuthInfos:  map[string]*api.AuthInfo{}, // AuthInfos is a map of referencable names to user configs
		Contexts:   map[string]*api.Context{},  // Contexts is a map of referencable names to context configs
	}

	// Craft kubeconfig
	// example: gke_my-project_us-central1-b_cluster-1 => https://XX.XX.XX.XX
	kName := fmt.Sprintf("gke_%s_%s_%s", projectID, cluster.Location, cluster.Name)
	cert, err := base64.StdEncoding.DecodeString(cluster.MasterAuth.ClusterCaCertificate)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate cluster=%s cert=%s: %w", kName, cluster.MasterAuth.ClusterCaCertificate, err)
	}
	ret.Clusters[kName] = &api.Cluster{
		CertificateAuthorityData: cert,
		Server:                   "https://" + cluster.Endpoint,
	}
	// Just reuse the context name as an auth name.
	ret.Contexts[kName] = &api.Context{
		Cluster:  kName,
		AuthInfo: kName,
	}
	// GCP specific configation; use cloud platform scope.
	ret.AuthInfos[kName] = &api.AuthInfo{
		Token: tok.AccessToken,
	}

	ret.CurrentContext = kName

	return &ret, nil
}

func (g *Global) initK8s(ctx context.Context) error {
	log := clog.FromContext(ctx)

	var cfg *rest.Config
	if g.ClusterName != "" {
		kubeConfig, err := getK8sClusterConfig(ctx, g.ProjectID, g.ClusterLocation, g.ClusterName)
		if err != nil {
			return fmt.Errorf("getting gke cluster config: %w", err)
		}

		if len(kubeConfig.Clusters) != 1 {
			return fmt.Errorf("got %d clusters in config, expected 1", len(kubeConfig.Clusters))
		}

		clusterName := maps.Keys(kubeConfig.Clusters)[0]
		config, err := clientcmd.NewNonInteractiveClientConfig(*kubeConfig, clusterName, &clientcmd.ConfigOverrides{}, nil).ClientConfig()
		if err != nil {
			return fmt.Errorf("creating k8s config cluster=%s: %w", clusterName, err)
		}
		cfg = config
	} else {
		config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{}).ClientConfig()
		if err != nil {
			return fmt.Errorf("creating default k8s config: %w", err)
		}
		cfg = config
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("creating k8s client: %w", err)
	}

	log.Debugf("ensuring namespace %s exists", g.K8sNamespace)
	if _, err := clientset.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: g.K8sNamespace,
		},
	}, metav1.CreateOptions{}); err != nil {
		if !k8serrors.IsAlreadyExists(err) {
			return fmt.Errorf("creating namespace: %w", err)
		}
	}

	log.Debugf("ensuring service account %s exists", g.ServiceAccount)
	if _, err := clientset.CoreV1().ServiceAccounts(g.K8sNamespace).Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      g.ServiceAccount,
			Namespace: g.K8sNamespace,
		},
	}, metav1.CreateOptions{}); err != nil {
		if !k8serrors.IsAlreadyExists(err) {
			return fmt.Errorf("creating service account: %w", err)
		}
	}

	g.clientset = clientset

	return nil
}
