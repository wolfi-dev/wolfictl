package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/apk/auth"
	"chainguard.dev/apko/pkg/apk/client"
	sbomSyft "github.com/anchore/syft/syft/sbom"
	"github.com/chainguard-dev/clog"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/buildlog"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/scanfindings"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/sbom"
	"github.com/wolfi-dev/wolfictl/pkg/scan"
	"github.com/wolfi-dev/wolfictl/pkg/versions"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/errgroup"
)

const (
	outputFormatOutline = "outline"
	outputFormatJSON    = "json"
)

var validOutputFormats = []string{outputFormatOutline, outputFormatJSON}

func cmdScan() *cobra.Command {
	p := &scanParams{}
	cmd := &cobra.Command{
		Use:   "scan [ --sbom | --build-log | --remote ] [ --advisory-filter <type> --advisories-repo-dir <path> ] target...",
		Short: "Scan a package for vulnerabilities",
		Long: `This command scans one or more distro packages for vulnerabilities.

## SCANNING

There are four ways to specify the package(s) to scan:

1. Specify the path to the APK file(s) to scan.

2. Specify the path to the APK SBOM file(s) to scan. (The SBOM is expected to
   use the Syft JSON format and can be created with the "wolfictl sbom -o
   syft-json ..." command.)

3. Specify the path to a Melange build log file (or to a directory that
   contains a build log file named "packages.log"). The build log file will be
   parsed to find the APK files to scan.

4. Specify the name(s) of package(s) in the Wolfi package repository. The
   latest versions of the package(s) for all supported architectures will be
   downloaded from the Wolfi package repository and scanned.

## FILTERING

By default, the command will print all vulnerabilities found in the package(s)
to stdout. You can filter the vulnerabilities shown using existing local
advisory data. To do this, you must first clone the advisory data from the
advisories repository for the distro whose packages you are scanning. You
specify the path to the local advisories repository using the
--advisories-repo-dir flag for the repository. Then, you can use the
"--advisory-filter" flag to specify which set of advisories to use for
filtering. The following sets of advisories are available:

- "resolved": Only filter out vulnerabilities that have been resolved in the
  distro.

- "all": Filter out all vulnerabilities that are referenced from any advisory
  in the advisories repository.

- "concluded": Only filter out all vulnerabilities that have been fixed, or those
  where no change is planned to fix the vulnerability.

## OUTPUT

When a scan finishes, the command will print the results to stdout. There are
two modes of output that can be specified with the --output (or "-o") flag:

- "outline": This is the default output mode. It prints the results in a
  human-readable outline format.

- "json": This mode prints the results in JSON format. This mode is useful for
  machine processing of the results.

The command will exit with a non-zero exit code if any errors occur during the
scan.

The command will also exit with a non-zero exit code if any vulnerabilities are
found and the --require-zero flag is specified.

`,
		Example: `
# Scan a single APK file
wolfictl scan /path/to/package.apk

# Scan multiple APK files
wolfictl scan /path/to/package1.apk /path/to/package2.apk

# Scan a single SBOM file
wolfictl scan /path/to/package.sbom --sbom

# Scan a directory containing a build log file
wolfictl scan /path/to/build/log/dir --build-log

# Scan a single package in the Wolfi package repository
wolfictl scan package-name --remote

# Scan multiple packages in the Wolfi package repository
wolfictl scan package1 package2 --remote
`,
		Args:          cobra.MinimumNArgs(1),
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := clog.NewLogger(newLogger(p.verbosity))
			ctx := clog.WithLogger(cmd.Context(), logger)

			if p.outputFormat == "" {
				p.outputFormat = outputFormatOutline
			}

			// Validate inputs

			if !slices.Contains(validOutputFormats, p.outputFormat) {
				return fmt.Errorf(
					"invalid output format %q, must be one of [%s]",
					p.outputFormat,
					strings.Join(validOutputFormats, ", "),
				)
			}

			if p.packageBuildLogInput && p.sbomInput ||
				p.packageBuildLogInput && p.remoteScanning ||
				p.sbomInput && p.remoteScanning {
				return errors.New("cannot specify more than one of [--build-log, --sbom, --remote]")
			}

			if p.triageWithGoVulnCheck && p.sbomInput {
				return errors.New("cannot specify both -s/--sbom and --govulncheck (govulncheck needs access to actual Go binaries)")
			}

			if p.advisoryFilterSet != "" {
				if !slices.Contains(scan.ValidAdvisoriesSets, p.advisoryFilterSet) {
					return fmt.Errorf(
						"invalid advisory filter set %q, must be one of [%s]",
						p.advisoryFilterSet,
						strings.Join(scan.ValidAdvisoriesSets, ", "),
					)
				}

				if p.advisoriesRepoDir == "" {
					return errors.New("advisory-based filtering requested, but no advisories repo dir was provided")
				}

				logger.Info("scan results will be filtered using advisory data", "filterSet", p.advisoryFilterSet, "advisoriesRepoDir", p.advisoriesRepoDir)
			}

			var advisoryDocumentIndex *configs.Index[v2.Document]

			if p.advisoriesRepoDir != "" {
				dir := p.advisoriesRepoDir
				advisoryFsys := rwos.DirFS(dir)
				index, err := v2.NewIndex(cmd.Context(), advisoryFsys)
				if err != nil {
					return fmt.Errorf("unable to index advisory configs for directory %q: %w", dir, err)
				}
				advisoryDocumentIndex = index
			}

			// TODO: This is a bit of a hack because MultiAuthenticator uses Basic auth to
			// determine when it should quit. so it's important that gcloudAuth goes last.
			auth.DefaultAuthenticators = auth.MultiAuthenticator(auth.DefaultAuthenticators, &gcloudAuth{})

			inputs, cleanup, err := p.resolveInputsToScan(ctx, args)
			if err != nil {
				return err
			}
			if cleanup != nil {
				defer func() {
					if err := cleanup(); err != nil {
						logger.Error("failed to clean up", "error", err)
						return
					}

					logger.Debug("cleaned up after scan")
				}()
			}

			scans, inputPathsFailingRequireZero, err := scanEverything(ctx, p, inputs, advisoryDocumentIndex)
			if err != nil {
				return err
			}

			if p.outputFormat == outputFormatJSON {
				enc := json.NewEncoder(os.Stdout)
				err := enc.Encode(scans)
				if err != nil {
					return fmt.Errorf("failed to marshal scans to JSON: %w", err)
				}
			}

			if len(inputPathsFailingRequireZero) > 0 {
				return fmt.Errorf("vulnerabilities found in the following package(s):\n%s", strings.Join(inputPathsFailingRequireZero, "\n"))
			}

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

func scanEverything(ctx context.Context, p *scanParams, inputs []string, advisoryDocumentIndex *configs.Index[v2.Document]) ([]scan.Result, []string, error) {
	// We're going to generate the SBOMs concurrently, then scan them sequentially.
	var g errgroup.Group
	g.SetLimit(runtime.GOMAXPROCS(0) + 1)

	// done is a slice of pseudo-promises that get closed when sboms[i] and files[i] are ready to scan.
	// We do this to keep a deterministic scan order, which maybe we don't actually care about.
	done := make([]chan struct{}, len(inputs))
	for i := range inputs {
		done[i] = make(chan struct{})
	}

	sboms := make([]*sbomSyft.SBOM, len(inputs))
	files := make([]*os.File, len(inputs))
	scans := make([]scan.Result, len(inputs))
	errs := make([]error, len(inputs))

	var inputPathsFailingRequireZero []string

	opts := scan.DefaultOptions
	opts.UseCPEs = p.useCPEMatching
	opts.PathOfDatabaseArchiveToImport = p.localDBFilePath

	// Immediately start a goroutine, so we can initialize the vulnerability database.
	// Once that's finished, we will start to pull sboms off of done as they become ready.
	g.Go(func() error {
		scanner, err := scan.NewScanner(opts)
		if err != nil {
			return fmt.Errorf("failed to create scanner: %w", err)
		}
		defer scanner.Close()

		for i, ch := range done {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ch:
			}

			input := inputs[i]

			if err := errs[i]; err != nil {
				if p.outputFormat == outputFormatOutline {
					fmt.Printf("❌ Skipping scan because SBOM generation failed for %q: %v\n", input, err)
					continue
				}
			}

			file := files[i]
			apkSBOM := sboms[i]

			if p.outputFormat == outputFormatOutline {
				fmt.Printf("🔎 Scanning %q\n", input)
			}

			result, err := p.doScanCommandForSingleInput(ctx, scanner, file, apkSBOM, advisoryDocumentIndex)
			if err != nil {
				return fmt.Errorf("failed to scan %q: %w", input, err)
			}

			scans[i] = *result

			if p.requireZeroFindings && len(result.Findings) > 0 {
				// Accumulate the list of failures to be returned at the end, but we still want to complete all scans
				inputPathsFailingRequireZero = append(inputPathsFailingRequireZero, inputs[i])
			}
		}

		return nil
	})

	tmpdir, err := os.MkdirTemp("", "wolfictl-scan-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(tmpdir)

	for i, input := range inputs {
		i, input := i, input

		g.Go(func() error {
			f := func() error {
				inputFile, err := resolveInputFileFromArg(ctx, tmpdir, input)
				if err != nil {
					return fmt.Errorf("failed to open input file: %w", err)
				}

				// Get the SBOM of the APK
				apkSBOM, err := p.generateSBOM(ctx, inputFile)
				if err != nil {
					return fmt.Errorf("failed to generate SBOM: %w", err)
				}

				sboms[i] = apkSBOM
				files[i] = inputFile

				return nil
			}

			errs[i] = f()

			// Signals to the other goroutine that inputs[i] is ready to scan.
			close(done[i])

			return nil
		})
	}

	return scans, inputPathsFailingRequireZero, errors.Join(g.Wait(), errors.Join(errs...))
}

type scanParams struct {
	requireZeroFindings   bool
	localDBFilePath       string
	outputFormat          string
	sbomInput             bool
	packageBuildLogInput  bool
	distro                string
	advisoryFilterSet     string
	advisoriesRepoDir     string
	disableSBOMCache      bool
	triageWithGoVulnCheck bool
	remoteScanning        bool
	useCPEMatching        bool
	verbosity             int
}

func (p *scanParams) addFlagsTo(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&p.requireZeroFindings, "require-zero", false, "exit 1 if any vulnerabilities are found")
	cmd.Flags().StringVar(&p.localDBFilePath, "local-file-grype-db", "", "import a local grype db file")
	cmd.Flags().StringVarP(&p.outputFormat, "output", "o", "", fmt.Sprintf("output format (%s), defaults to %s", strings.Join(validOutputFormats, "|"), outputFormatOutline))
	cmd.Flags().BoolVarP(&p.sbomInput, "sbom", "s", false, "treat input(s) as SBOM(s) of APK(s) instead of as actual APK(s)")
	cmd.Flags().BoolVar(&p.packageBuildLogInput, "build-log", false, "treat input as a package build log file (or a directory that contains a packages.log file)")
	cmd.Flags().StringVar(&p.distro, "distro", "wolfi", "distro to use during vulnerability matching")
	cmd.Flags().StringVarP(&p.advisoryFilterSet, "advisory-filter", "f", "", fmt.Sprintf("exclude vulnerability matches that are referenced from the specified set of advisories (%s)", strings.Join(scan.ValidAdvisoriesSets, "|")))
	addAdvisoriesDirFlag(&p.advisoriesRepoDir, cmd)
	cmd.Flags().BoolVarP(&p.disableSBOMCache, "disable-sbom-cache", "D", false, "don't use the SBOM cache")
	cmd.Flags().BoolVar(&p.triageWithGoVulnCheck, "govulncheck", false, "EXPERIMENTAL: triage vulnerabilities in Go binaries using govulncheck")
	_ = cmd.Flags().MarkHidden("govulncheck") //nolint:errcheck
	cmd.Flags().BoolVarP(&p.remoteScanning, "remote", "r", false, "treat input(s) as the name(s) of package(s) in the Wolfi package repository to download and scan the latest versions of")
	cmd.Flags().BoolVar(&p.useCPEMatching, "use-cpes", false, "turn on all CPE matching in Grype")
	addVerboseFlag(&p.verbosity, cmd)
}

func (p *scanParams) resolveInputsToScan(ctx context.Context, args []string) (inputs []string, cleanup func() error, err error) {
	logger := clog.FromContext(ctx)

	switch {
	case p.packageBuildLogInput:
		if len(args) != 1 {
			return nil, nil, fmt.Errorf("must specify exactly one build log file (or a directory that contains a %q build log file)", buildlog.DefaultName)
		}

		var err error
		inputs, err = resolveInputFilePathsFromBuildLog(args[0])
		if err != nil {
			return nil, nil, fmt.Errorf("failed to resolve scan inputs from build log: %w", err)
		}
		logger.Debug("resolved inputs from build log", "inputs", strings.Join(inputs, ", "))

	case p.remoteScanning:
		// For each input, download the APK from the Wolfi package repository and update `inputs` to point to the downloaded APKs

		if p.outputFormat == outputFormatOutline {
			fmt.Println("📡 Finding remote packages")
		}

		return resolveInputsForRemoteTarget(ctx, args)

	default:
		inputs = args
	}

	return inputs, nil, nil
}

func (p *scanParams) doScanCommandForSingleInput(
	ctx context.Context,
	scanner *scan.Scanner,
	inputFile *os.File,
	apkSBOM *sbomSyft.SBOM,
	advisoryDocumentIndex *configs.Index[v2.Document],
) (*scan.Result, error) {
	log := clog.FromContext(ctx)

	result, err := scanner.APKSBOM(ctx, apkSBOM)
	if err != nil {
		return nil, fmt.Errorf("failed to scan APK: %w", err)
	}

	// If requested, triage vulnerabilities in Go binaries using govulncheck

	if p.triageWithGoVulnCheck {
		triagedFindings, err := scan.Triage(ctx, *result, inputFile)
		if err != nil {
			return nil, fmt.Errorf("failed to triage vulnerability matches: %w", err)
		}
		result.Findings = triagedFindings
	}

	inputFile.Close()

	// If requested, filter scan results using advisories

	if set := p.advisoryFilterSet; set != "" {
		findings, err := scan.FilterWithAdvisories(ctx, *result, advisoryDocumentIndex, set)
		if err != nil {
			return nil, fmt.Errorf("failed to filter scan results with advisories: %w", err)
		}

		result.Findings = findings
	}

	if advisoryDocumentIndex != nil {
		log.Debug("advisory data available for adding context to findings")

		entry, err := advisoryDocumentIndex.Select().WhereName(result.TargetAPK.Origin()).First()
		if err != nil {
			log.Warnf("failed to get advisory document for package %q: %v", result.TargetAPK.Origin(), err)
		}
		doc := entry.Configuration()

		// If requested, add advisory data to the scan results
		for i := range result.Findings {
			f := &result.Findings[i]
			if adv, ok := doc.Advisories.GetByAnyVulnerability(f.Vulnerability.Aliases...); ok {
				f.Advisory = &adv
				result.Findings[i] = *f
			}
		}
	}

	// Handle CLI options

	findings := result.Findings
	if p.outputFormat == outputFormatOutline {
		// Print output immediately
		render, err := scanfindings.Render(findings)
		if err != nil {
			return nil, err
		}
		fmt.Println(render)
	}

	return result, nil
}

func (p *scanParams) generateSBOM(ctx context.Context, f *os.File) (*sbomSyft.SBOM, error) {
	if p.sbomInput {
		return sbom.FromSyftJSON(f)
	}

	if p.disableSBOMCache {
		return sbom.Generate(ctx, f.Name(), f, p.distro)
	}

	return sbom.CachedGenerate(ctx, f.Name(), f, p.distro)
}

// resolveInputFilePathsFromBuildLog takes the given path to a Melange build log
// file (or a directory that contains the build log as a "packages.log" file).
// Once it finds the build log, it parses it, and returns a slice of file paths
// to APKs to be scanned. Each APK path is created with the assumption that the
// APKs are located at "$BASE/packages/$ARCH/$PACKAGE-$VERSION.apk", where $BASE
// is the buildLogPath if it's a directory, or the directory containing the
// buildLogPath if it's a file.
func resolveInputFilePathsFromBuildLog(buildLogPath string) ([]string, error) {
	pathToFileOrDirectory := filepath.Clean(buildLogPath)

	info, err := os.Stat(pathToFileOrDirectory)
	if err != nil {
		return nil, fmt.Errorf("failed to stat build log input: %w", err)
	}

	var pathToFile, packagesBaseDir string
	if info.IsDir() {
		pathToFile = filepath.Join(pathToFileOrDirectory, buildlog.DefaultName)
		packagesBaseDir = pathToFileOrDirectory
	} else {
		pathToFile = pathToFileOrDirectory
		packagesBaseDir = filepath.Dir(pathToFile)
	}

	file, err := os.Open(pathToFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open build log: %w", err)
	}
	defer file.Close()

	buildLogEntries, err := buildlog.Parse(file)
	if err != nil {
		return nil, fmt.Errorf("failed to parse build log: %w", err)
	}

	scanInputs := make([]string, 0, len(buildLogEntries))
	for _, entry := range buildLogEntries {
		apkName := fmt.Sprintf("%s-%s.apk", entry.Package, entry.FullVersion)
		apkPath := filepath.Join(packagesBaseDir, "packages", entry.Arch, apkName)
		scanInputs = append(scanInputs, apkPath)
	}

	return scanInputs, nil
}

// resolveInputFileFromArg figures out how to interpret the given input file path
// to find a file to scan. This input file could be either an APK or an SBOM.
// The objective of this function is to find the file to scan and return a file
// handle to it.
//
// In order, it will:
//
// 1. If the path is "-", read stdin into a temp file and return that.
//
// 2. If the path starts with "https://", download the remote file into a temp file and return that.
//
// 3. Otherwise, open the file at the given path and return that.
func resolveInputFileFromArg(ctx context.Context, tmpdir, inputFilePath string) (*os.File, error) {
	switch {
	case inputFilePath == "-":
		// Read stdin into a temp file.
		t, err := os.CreateTemp(tmpdir, "wolfictl-scan-")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp file for stdin: %w", err)
		}
		if _, err := io.Copy(t, os.Stdin); err != nil {
			return nil, err
		}
		if _, err := t.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}

		return t, nil

	case strings.HasPrefix(inputFilePath, "https://"):
		// Fetch the remote URL into a temp file.
		t, err := os.CreateTemp(tmpdir, "wolfictl-scan-")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp file for remote: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, inputFilePath, nil)
		if err != nil {
			return nil, err
		}
		if err := auth.DefaultAuthenticators.AddAuth(ctx, req); err != nil {
			return nil, fmt.Errorf("adding auth: %w", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to download from remote: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			all, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("failed to download from remote (%d): %s", resp.StatusCode, string(all))
		}
		if _, err := io.Copy(t, resp.Body); err != nil {
			return nil, err
		}
		if _, err := t.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}

		return t, nil

	default:
		inputFile, err := os.Open(inputFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to open input file: %w", err)
		}

		return inputFile, nil
	}
}

// resolveInputForRemoteTarget takes the given input string, which is expected
// to be the name of a  package (or subpackage), and it queries the indices
// to find the latest version of the package for the given architecture.
func resolveInputForRemoteTarget(ctx context.Context, indices map[string]map[string]*apk.APKIndex, arch, input string) (string, error) {
	logger := clog.FromContext(ctx)

	var (
		latestPkg     *apk.Package
		downloadURL   string
		latestVersion string
	)

	for apkRepositoryURL, byArch := range indices {
		apkindex, ok := byArch[arch]
		if !ok {
			return "", fmt.Errorf("missing arch %q for %q", arch, apkRepositoryURL)
		}
		nameMatches := lo.Filter(apkindex.Packages, func(pkg *apk.Package, _ int) bool {
			return pkg != nil && pkg.Name == input
		})

		if len(nameMatches) == 0 {
			continue
		}

		vers := lo.Map(nameMatches, func(pkg *apk.Package, _ int) string {
			return pkg.Version
		})

		sort.Sort(versions.ByLatestStrings(vers))

		// Use this latest version iff we haven't seen a greater version yet.
		got := vers[0]

		next, err := versions.NewVersion(got)
		if err != nil {
			logger.Warnf("invalid version %q: %v", got, err)
			continue
		}

		prev, err := versions.NewVersion(latestVersion)
		if err != nil {
			if latestVersion != "" {
				logger.Warnf("invalid version %q: %v", latestVersion, err)
			}
		} else if next.LessThanOrEqual(prev) {
			continue
		}

		latestVersion = got

		for _, pkg := range nameMatches {
			if pkg.Version == latestVersion {
				latestPkg = pkg
				downloadURL = fmt.Sprintf("%s/%s/%s", apkRepositoryURL, arch, latestPkg.Filename())
				break
			}
		}
	}

	if downloadURL == "" {
		logger.Warnf("no package found with name %q in arch %q but will continue, it might not have a package built for this arch.", input, arch)
		return "", nil
	}

	_, apkTempFileName, _ := strings.Cut(downloadURL, "://")
	apkTempFileName = strings.ReplaceAll(apkTempFileName, "/", "-")

	tmpFile, err := os.CreateTemp("", apkTempFileName)
	if err != nil {
		return "", fmt.Errorf("creating temp dir: %w", err)
	}
	apkTmpFilePath := tmpFile.Name()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating request for %q: %w", downloadURL, err)
	}

	if err := auth.DefaultAuthenticators.AddAuth(ctx, req); err != nil {
		return "", fmt.Errorf("adding auth: %w", err)
	}

	logger.Debug("downloading APK", "url", downloadURL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("downloading %q: %w", downloadURL, err)
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
			// TODO: Change this once we completely move over to apk.cgr.dev.
			return "", fmt.Errorf("downloading %q (status: %d) you may need to run 'gcloud auth login' to scan this package", downloadURL, resp.StatusCode)
		}
		return "", fmt.Errorf("downloading %q (status: %d)", downloadURL, resp.StatusCode)
	}
	_, err = io.Copy(tmpFile, resp.Body)
	if err != nil {
		return "", fmt.Errorf("saving contents of %q to %q: %w", downloadURL, apkTmpFilePath, err)
	}
	resp.Body.Close()
	if err := tmpFile.Close(); err != nil {
		return "", fmt.Errorf("closing %s: %w", apkTempFileName, err)
	}

	logger.Info("downloaded APK", "path", apkTmpFilePath)

	return apkTmpFilePath, nil
}

// resolveInputsForRemoteTarget takes the given input strings, which are expected
// to be the name of a package (or subpackage), and it queries the APK repositories
// to find the latest version of the packages for each architecture.
// It then downloads each APK and returns a slice of file paths to the downloaded APKs.
//
// For example, given the input value []string{"calico"}, this function will find the
// latest version of the package (e.g. "calico-3.26.3-r3.apk") and download it
// for each architecture.
func resolveInputsForRemoteTarget(ctx context.Context, inputs []string) (downloadedAPKFilePaths []string, cleanup func() error, err error) {
	var (
		mu sync.Mutex
		ig errgroup.Group
	)

	c := client.New(http.DefaultClient)
	indices := map[string]map[string]*apk.APKIndex{}
	for _, apkRepositoryURL := range []string{
		"https://packages.wolfi.dev/os",
		"https://apk.cgr.dev/chainguard-private",
		"https://apk.cgr.dev/extra-packages",
	} {
		byArch := map[string]*apk.APKIndex{}
		for _, arch := range []string{"x86_64", "aarch64"} {
			ig.Go(func() error {
				apkindex, err := c.GetRemoteIndex(ctx, apkRepositoryURL, arch)
				if err != nil {
					return fmt.Errorf("getting APKINDEX: %w", err)
				}

				mu.Lock()
				defer mu.Unlock()

				byArch[arch] = apkindex

				return nil
			})
		}

		indices[apkRepositoryURL] = byArch
	}

	if err := ig.Wait(); err != nil {
		return nil, nil, err
	}

	var (
		ag          errgroup.Group
		archesFound = map[string]int{}
	)

	for _, input := range inputs {
		for _, arch := range []string{"x86_64", "aarch64"} {
			ag.Go(func() error {
				apkTmpFilePath, err := resolveInputForRemoteTarget(ctx, indices, arch, input)
				if err != nil {
					return err
				}

				if apkTmpFilePath == "" {
					return nil
				}

				mu.Lock()
				defer mu.Unlock()

				// we found a package for this arch
				archesFound[input]++
				downloadedAPKFilePaths = append(downloadedAPKFilePaths, apkTmpFilePath)

				return nil
			})
		}
	}

	if err := ag.Wait(); err != nil {
		return nil, nil, err
	}

	for input, archesFound := range archesFound {
		if archesFound == 0 {
			return nil, nil, fmt.Errorf("no packages found with name %q in any arch", input)
		}
	}

	cleanup = func() error {
		var errs []error
		for _, path := range downloadedAPKFilePaths {
			if err := os.Remove(path); err != nil {
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			return fmt.Errorf("failed to clean up downloaded APKs: %w", errors.Join(errs...))
		}
		return nil
	}

	return downloadedAPKFilePaths, cleanup, nil
}

type gcloudAuth struct {
	once sync.Once
	tok  string
	err  error
}

func (g *gcloudAuth) AddAuth(ctx context.Context, req *http.Request) error {
	if req.Host != "packages.cgr.dev" {
		return nil
	}

	g.once.Do(func() {
		cmd := exec.CommandContext(ctx, "gcloud", "auth", "print-access-token")
		cmd.Stderr = os.Stderr

		out, err := cmd.Output()
		if err != nil {
			g.err = err
		} else {
			g.tok = strings.TrimSpace(string(out))
		}
	})

	if g.err != nil {
		return g.err
	}

	req.Header.Set("Authorization", "Bearer "+g.tok)

	return nil
}
