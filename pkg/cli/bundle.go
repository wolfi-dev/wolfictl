package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing/fstest"

	"chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/wolfi-dev/wolfictl/pkg/dag"
	"github.com/wolfi-dev/wolfictl/pkg/internal/bundle"
)

func cmdBundle() *cobra.Command {
	cfg := global{}
	bcfg := bundleConfig{
		base: empty.Index,
	}

	cmd := &cobra.Command{
		Use:           "bundle",
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			if cfg.signingKey == "" {
				cfg.signingKey = filepath.Join(cfg.dir, "local-melange.rsa")
			}
			if cfg.pipelineDir == "" {
				cfg.pipelineDir = filepath.Join(cfg.dir, "pipelines")
			}
			if cfg.outDir == "" {
				cfg.outDir = filepath.Join(cfg.dir, "packages")
			}

			if bcfg.baseRef != "" {
				ref, err := name.ParseReference(bcfg.baseRef, name.Insecure)
				if err != nil {
					return err
				}
				bcfg.base, err = remote.Index(ref)
				if err != nil {
					return err
				}
			}

			if bcfg.repo != "" {
				pusher, err := remote.NewPusher(remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithUserAgent("wolfictl bundle"))
				if err != nil {
					return err
				}
				bcfg.pusher = pusher

				bcfg.dirfs = os.DirFS(cfg.dir)

				bcfg.commonFiles, err = commonFS(bcfg.dirfs)
				if err != nil {
					return err
				}
			}

			return bundleAll(ctx, &cfg, &bcfg, args)
		},
	}

	cmd.Flags().StringVarP(&cfg.dir, "dir", "d", ".", "directory to search for melange configs")
	cmd.Flags().StringVar(&cfg.pipelineDir, "pipeline-dir", "", "directory used to extend defined built-in pipelines")
	cmd.Flags().StringVar(&cfg.runner, "runner", "docker", "which runner to use to enable running commands, default is based on your platform.")
	cmd.Flags().StringSliceVar(&cfg.archs, "arch", []string{"x86_64", "aarch64"}, "arch of package to build")
	cmd.Flags().BoolVar(&cfg.dryrun, "dry-run", false, "print commands instead of executing them")
	cmd.Flags().StringSliceVarP(&cfg.extraKeys, "keyring-append", "k", []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"}, "path to extra keys to include in the build environment keyring")
	cmd.Flags().StringSliceVarP(&cfg.extraRepos, "repository-append", "r", []string{"https://packages.wolfi.dev/os"}, "path to extra repositories to include in the build environment")
	cmd.Flags().StringSliceVar(&cfg.fuses, "gcsfuse", []string{}, "list of gcsfuse mounts to make available to the build environment (e.g. gs://my-bucket/subdir:/mnt/my-bucket)")
	cmd.Flags().StringVar(&cfg.signingKey, "signing-key", "", "key to use for signing")
	cmd.Flags().StringVar(&cfg.namespace, "namespace", "wolfi", "namespace to use in package URLs in SBOM (eg wolfi, alpine)")
	cmd.Flags().StringVar(&cfg.outDir, "out-dir", "", "directory where packages will be output")
	cmd.Flags().StringVar(&cfg.cacheDir, "cache-dir", "./melange-cache/", "directory used for cached inputs")
	cmd.Flags().StringVar(&cfg.cacheSource, "cache-source", "", "directory or bucket used for preloading the cache")
	cmd.Flags().BoolVar(&cfg.generateIndex, "generate-index", true, "whether to generate APKINDEX.tar.gz")
	cmd.Flags().StringVar(&cfg.dst, "destination-repository", "", "repo where packages will eventually be uploaded, used to skip existing packages (currently only supports http)")
	cmd.Flags().StringVar(&bcfg.baseRef, "bundle-base", "", "base image used for melange build bundles")
	cmd.Flags().StringVar(&bcfg.repo, "bundle-repo", "", "where to push the bundles")

	return cmd
}

type bundleConfig struct {
	baseRef     string
	base        v1.ImageIndex
	repo        string
	commonFiles fs.FS
	pusher      *remote.Pusher

	dirfs fs.FS
}

func bundleAll(ctx context.Context, cfg *global, bcfg *bundleConfig, args []string) error { //nolint:gocyclo
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
			bcfg:   bcfg,
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

	// We're ok with Info level from here on.
	log := clog.FromContext(ctx)

	built := map[string]*task{}
	srcfs := fstest.MapFS{}

	errs := []error{}
	for _, t := range todos {
		if err := t.addBundle(ctx, srcfs, built); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) != 0 {
		log.Errorf("Failed to bundle %d builds", len(errs))
		return errors.Join(errs...)
	}

	needed, err := stuff.g.Filter(func(pkg dag.Package) bool {
		_, ok := built[pkg.Name()]
		return ok
	})
	if err != nil {
		return err
	}

	m, err := needed.Graph.AdjacencyMap()
	if err != nil {
		return err
	}
	log.Infof("bundle contains %d builds", len(m))

	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	layer := static.NewLayer(b, ggcrtypes.MediaType("application/vnd.dev.wolfi.graph+json"))
	depgraph, err := mutate.AppendLayers(mutate.MediaType(empty.Image, ggcrtypes.OCIManifestSchema1), layer)
	if err != nil {
		return err
	}

	// First is dependency graph.
	addendums := []mutate.IndexAddendum{{
		Add: depgraph,
		Descriptor: v1.Descriptor{
			Annotations: map[string]string{
				"dev.wolfi.bundle": "graph",
			},
		},
	}}

	// Second is all the metadata.
	bundleTasks := make([]bundle.Task, 0, len(built))
	for pkg, t := range built {
		subpkgs := make([]string, 0, len(t.config.Subpackages))
		for _, sp := range t.config.Subpackages { //nolint:gocritic
			subpkgs = append(subpkgs, sp.Name)
		}
		bundleTasks = append(bundleTasks, bundle.Task{
			Package:       pkg,
			Version:       t.config.Package.Version,
			Epoch:         t.config.Package.Epoch,
			Path:          t.config.Path,
			SourceDir:     filepath.Join(t.cfg.dir, t.pkg),
			Architectures: t.archs,
			Subpackages:   subpkgs,
			Resources:     t.config.Package.Resources,
		})
	}

	tb, err := json.Marshal(bundleTasks)
	if err != nil {
		return err
	}
	tlayer := static.NewLayer(tb, ggcrtypes.MediaType("application/vnd.dev.wolfi.tasks+json"))
	taskimg, err := mutate.AppendLayers(mutate.MediaType(empty.Image, ggcrtypes.OCIManifestSchema1), tlayer)
	if err != nil {
		return err
	}

	addendums = append(addendums, mutate.IndexAddendum{
		Add: taskimg,
		Descriptor: v1.Descriptor{
			Annotations: map[string]string{
				"dev.wolfi.bundle": "tasks",
			},
		},
	})

	if bcfg.repo != "" {
		entrypoints := map[types.Architecture]*bundle.Entrypoint{}

		for _, arch := range cfg.archs {
			flags := []string{
				"--arch=" + arch,
				"--env-file=" + envFile(arch),
				"--runner=" + cfg.runner,
				"--namespace=" + cfg.namespace,
				"--signing-key=" + cfg.signingKey,
				"--pipeline-dir=" + cfg.pipelineDir,
			}

			for _, k := range cfg.extraKeys {
				flags = append(flags, "--keyring-append="+k)
			}

			for _, r := range cfg.extraRepos {
				flags = append(flags, "--repository-append="+r)
			}

			mounts := make([]*bundle.GCSFuseMount, 0, len(cfg.fuses))
			for _, f := range cfg.fuses {
				mount, err := bundle.ParseGCSFuseMount(f)
				if err != nil {
					return err
				}
				mounts = append(mounts, mount)
			}

			entrypoints[types.ParseArchitecture(arch)] = &bundle.Entrypoint{
				Flags:         flags,
				GCSFuseMounts: mounts,
			}
		}

		bundled, err := bundle.New(bcfg.base, entrypoints, bcfg.commonFiles, srcfs)
		if err != nil {
			return err
		}

		addendums = append(addendums, mutate.IndexAddendum{
			Add: bundled,
			Descriptor: v1.Descriptor{
				Annotations: map[string]string{
					"dev.wolfi.bundle": "runtime",
				},
			},
		})
	}

	idx := mutate.AppendManifests(empty.Index, addendums...)
	dst, err := name.ParseReference(fmt.Sprintf("%s/%s", bcfg.repo, "bundle"), name.Insecure)
	if err != nil {
		return err
	}

	log.Infof("pushing bundle to %s", dst.String())

	if err := bcfg.pusher.Push(ctx, dst, idx); err != nil {
		return fmt.Errorf("pushing %s: %w", dst, err)
	}

	digest, err := idx.Digest()
	if err != nil {
		return err
	}

	log.Infof("pushed bundle to %s", dst.Context().Digest(digest.String()).String())
	fmt.Println(dst.Context().Digest(digest.String()).String())

	return nil
}

func (t *task) addBundle(ctx context.Context, srcfs fstest.MapFS, built map[string]*task) error {
	if t.done {
		return nil
	}

	log := clog.FromContext(ctx)

	log.Infof("bundle(%q)", t.pkg)

	needsIndex := map[string]bool{}

	for _, arch := range t.archs {
		apkFile := t.pkgver() + ".apk"

		// See if we already have the package indexed.
		if _, ok := t.cfg.exists[arch][apkFile]; ok {
			log.Infof("Skipping %s/%s, already indexed", arch, apkFile)
			continue
		}

		needsIndex[arch] = true
	}

	if len(needsIndex) == 0 {
		return nil
	}

	if err := t.addSourceFS(srcfs, t.bcfg.dirfs); err != nil {
		return fmt.Errorf("addSourceFS %s: %w", t.pkg, err)
	}

	built[t.pkg] = t
	t.done = true

	for _, dep := range t.deps {
		if err := dep.addBundle(ctx, srcfs, built); err != nil {
			return fmt.Errorf("addBundle %s: %w", dep.pkg, err)
		}
	}

	return nil
}

func (t *task) addSourceFS(mapfs fstest.MapFS, dirfs fs.FS) error {
	sdir, err := t.sourceDir()
	if err != nil {
		return err
	}

	filename := t.config.Path

	data, err := fs.ReadFile(dirfs, filename)
	if err != nil {
		return err
	}
	info, err := fs.Stat(dirfs, filename)
	if err != nil {
		return err
	}

	mapfs[filename] = &fstest.MapFile{
		Data:    data,
		Mode:    info.Mode(),
		ModTime: info.ModTime(),
	}

	if err := fs.WalkDir(dirfs, sdir, func(p string, d fs.DirEntry, _ error) error {
		info, err := d.Info()
		if err != nil {
			return err
		}
		mapf := &fstest.MapFile{
			Mode:    info.Mode(),
			ModTime: info.ModTime(),
		}

		if !info.IsDir() {
			mapf.Data, err = fs.ReadFile(dirfs, p)
			if err != nil {
				return err
			}
		}

		mapfs[p] = mapf

		return nil
	}); err != nil {
		return err
	}

	return nil
}

func commonFS(dirfs fs.FS) (fs.FS, error) {
	mapfs := fstest.MapFS{}

	envs, err := fs.Glob(dirfs, "build-*.env")
	if err != nil {
		return nil, err
	}
	for _, name := range envs {
		data, err := fs.ReadFile(dirfs, name)
		if err != nil {
			return nil, err
		}
		info, err := fs.Stat(dirfs, name)
		if err != nil {
			return nil, err
		}

		mapfs[name] = &fstest.MapFile{
			Data:    data,
			Mode:    info.Mode(),
			ModTime: info.ModTime(),
		}
	}

	if err := fs.WalkDir(dirfs, "pipelines", func(p string, d fs.DirEntry, _ error) error {
		info, err := d.Info()
		if err != nil {
			return err
		}
		mapf := &fstest.MapFile{
			Mode:    info.Mode(),
			ModTime: info.ModTime(),
		}

		if !info.IsDir() {
			mapf.Data, err = fs.ReadFile(dirfs, p)
			if err != nil {
				return err
			}
		}

		mapfs[p] = mapf

		return nil
	}); err != nil {
		return nil, err
	}

	return mapfs, nil
}

func envFile(arch string) string {
	return fmt.Sprintf("build-%s.env", arch)
}
