package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	sbomSyft "github.com/anchore/syft/syft/sbom"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/go-apk/pkg/apk"
	"github.com/charmbracelet/lipgloss"
	"github.com/samber/lo"
	"github.com/savioxavier/termlink"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/buildlog"
	"github.com/wolfi-dev/wolfictl/pkg/cli/styles"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/index"
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

## AUTO-TRIAGING

Wolfictl now supports auto-triaging vulnerabilities found in Go binaries using
govulncheck. To enable this feature, use the "--govulncheck" flag. Note that
this feature is experimental and may not work in all cases. For more
information on the govulncheck utility, see
https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck. Using this feature does
not require you to install govulncheck on your system (the functionality
required is included in wolfictl as a library).

For vulnerabilities known to govulncheck, this feature annotates each
vulnerability with a "true positive" or "false positive" designation. The JSON
output mode shows more information about the govulncheck triage results than
the default outline output mode.

This feature does not filter out any results from the scan output.

This feature is only supported when scanning APKs, not when scanning SBOMs.

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
				if p.advisoryFilterSet == "" {
					return errors.New("advisories repo dir provided, but no advisory filter set was specified (see -f/--advisory-filter)")
				}

				dir := p.advisoriesRepoDir
				advisoryFsys := rwos.DirFS(dir)
				index, err := v2.NewIndex(cmd.Context(), advisoryFsys)
				if err != nil {
					return fmt.Errorf("unable to index advisory configs for directory %q: %w", dir, err)
				}
				advisoryDocumentIndex = index
			}

			inputs, cleanup, err := p.resolveInputsToScan(ctx, args)
			if err != nil {
				return err
			}
			defer func() {
				if err := cleanup(); err != nil {
					logger.Error("failed to clean up", "error", err)
					return
				}

				logger.Debug("cleaned up after scan")
			}()

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

	// Immediately start a goroutine, so we can initialize the vulnerability database.
	// Once that's finished, we will start to pull sboms off of done as they become ready.
	g.Go(func() error {
		scanner, err := scan.NewScanner(p.localDBFilePath, p.useCPEMatching)
		if err != nil {
			return fmt.Errorf("failed to create scanner: %w", err)
		}

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

	for i, input := range inputs {
		i, input := i, input

		g.Go(func() error {
			f := func() error {
				inputFile, err := resolveInputFileFromArg(input)
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
	cmd.Flags().BoolVar(&p.disableSBOMCache, "disable-sbom-cache", false, "don't use the SBOM cache")
	cmd.Flags().BoolVar(&p.triageWithGoVulnCheck, "govulncheck", false, "EXPERIMENTAL: triage vulnerabilities in Go binaries using govulncheck")
	_ = cmd.Flags().MarkHidden("govulncheck") //nolint:errcheck
	cmd.Flags().BoolVarP(&p.remoteScanning, "remote", "r", false, "treat input(s) as the name(s) of package(s) in the Wolfi package repository to download and scan the latest versions of")
	cmd.Flags().BoolVar(&p.useCPEMatching, "use-cpes", false, "turn on all CPE matching in Grype")
	addVerboseFlag(&p.verbosity, cmd)
}

func (p *scanParams) resolveInputsToScan(ctx context.Context, args []string) (inputs []string, cleanup func() error, err error) {
	logger := clog.FromContext(ctx)

	var cleanupFuncs []func() error
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

		for _, arg := range args {
			targetPaths, cleanup, err := resolveInputForRemoteTarget(ctx, arg)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to resolve input %q for remote scanning: %w", arg, err)
			}
			inputs = append(inputs, targetPaths...)
			cleanupFuncs = append(cleanupFuncs, cleanup)
		}

	default:
		inputs = args
	}

	cleanup = func() error {
		var errs []error
		for _, f := range cleanupFuncs {
			if f == nil {
				continue
			}
			if err := f(); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}

	return inputs, cleanup, nil
}

func (p *scanParams) doScanCommandForSingleInput(
	ctx context.Context,
	scanner *scan.Scanner,
	inputFile *os.File,
	apkSBOM *sbomSyft.SBOM,
	advisoryDocumentIndex *configs.Index[v2.Document],
) (*scan.Result, error) {
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

	// Handle CLI options

	findings := result.Findings
	if p.outputFormat == outputFormatOutline {
		// Print output immediately

		if len(findings) == 0 {
			fmt.Println("✅ No vulnerabilities found")
		} else {
			tree := newFindingsTree(findings)
			fmt.Println(tree.render())
		}
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
func resolveInputFileFromArg(inputFilePath string) (*os.File, error) {
	switch {
	case inputFilePath == "-":
		// Read stdin into a temp file.
		t, err := os.CreateTemp("", "wolfictl-scan-")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp file for stdin: %w", err)
		}
		if _, err := io.Copy(t, os.Stdin); err != nil {
			return nil, err
		}
		if err := t.Close(); err != nil {
			return nil, err
		}

		return t, nil

	case strings.HasPrefix(inputFilePath, "https://"):
		// Fetch the remote URL into a temp file.
		t, err := os.CreateTemp("", "wolfictl-scan-")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp file for remote: %w", err)
		}
		resp, err := http.Get(inputFilePath) //nolint:gosec
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
		if err := t.Close(); err != nil {
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
// to be the name of a Wolfi package (or subpackage), and it queries the Wolfi
// APK repository to find the latest version of the package for each
// architecture. It then downloads each APK and returns a slice of file paths to
// the downloaded APKs.
//
// For example, given the input value "calico", this function will find the
// latest version of the package (e.g. "calico-3.26.3-r3.apk") and download it
// for each architecture.
func resolveInputForRemoteTarget(ctx context.Context, input string) (downloadedAPKFilePaths []string, cleanup func() error, err error) {
	logger := clog.FromContext(ctx)

	for _, arch := range []string{"x86_64", "aarch64"} {
		const apkRepositoryURL = "https://packages.wolfi.dev/os"
		apkindex, err := index.Index(arch, apkRepositoryURL)
		if err != nil {
			return nil, nil, fmt.Errorf("getting APKINDEX: %w", err)
		}

		nameMatches := lo.Filter(apkindex.Packages, func(pkg *apk.Package, _ int) bool {
			return pkg != nil && pkg.Name == input
		})

		if len(nameMatches) == 0 {
			return nil, nil, fmt.Errorf("no Wolfi package found with name %q in arch %q", input, arch)
		}

		vers := lo.Map(nameMatches, func(pkg *apk.Package, _ int) string {
			return pkg.Version
		})

		sort.Sort(versions.ByLatestStrings(vers))
		latestVersion := vers[0]

		var latestPkg *apk.Package
		for _, pkg := range nameMatches {
			if pkg.Version == latestVersion {
				latestPkg = pkg
				break
			}
		}
		downloadURL := fmt.Sprintf("%s/%s/%s", apkRepositoryURL, arch, latestPkg.Filename())

		apkTempFileName := fmt.Sprintf("%s-%s-%s-*.apk", arch, input, latestVersion)
		tmpFile, err := os.CreateTemp("", apkTempFileName)
		if err != nil {
			return nil, nil, fmt.Errorf("creating temp dir: %w", err)
		}
		apkTmpFilePath := tmpFile.Name()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("creating request for %q: %w", downloadURL, err)
		}

		logger.Debug("downloading APK", "url", downloadURL)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, nil, fmt.Errorf("downloading %q: %w", downloadURL, err)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, nil, fmt.Errorf("downloading %q (status: %d): %w", downloadURL, resp.StatusCode, err)
		}
		_, err = io.Copy(tmpFile, resp.Body)
		if err != nil {
			return nil, nil, fmt.Errorf("saving contents of %q to %q: %w", downloadURL, apkTmpFilePath, err)
		}
		resp.Body.Close()
		tmpFile.Close()

		logger.Info("downloaded APK", "path", apkTmpFilePath)

		downloadedAPKFilePaths = append(downloadedAPKFilePaths, apkTmpFilePath)
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

type findingsTree struct {
	findingsByPackageByLocation map[string]map[string][]scan.Finding
	packagesByID                map[string]scan.Package
}

func newFindingsTree(findings []scan.Finding) *findingsTree {
	tree := make(map[string]map[string][]scan.Finding)
	packagesByID := make(map[string]scan.Package)

	for i := range findings {
		f := findings[i]
		loc := f.Package.Location
		packageID := f.Package.ID
		packagesByID[packageID] = f.Package

		if _, ok := tree[loc]; !ok {
			tree[loc] = make(map[string][]scan.Finding)
		}

		tree[loc][packageID] = append(tree[loc][packageID], f)
	}

	return &findingsTree{
		findingsByPackageByLocation: tree,
		packagesByID:                packagesByID,
	}
}

func (t findingsTree) render() string {
	locations := lo.Keys(t.findingsByPackageByLocation)
	sort.Strings(locations)

	var lines []string
	for i, location := range locations {
		var treeStem, verticalLine string
		if i == len(locations)-1 {
			treeStem = "└── "
			verticalLine = " "
		} else {
			treeStem = "├── "
			verticalLine = "│"
		}

		line := treeStem + fmt.Sprintf("📄 %s", location)
		lines = append(lines, line)

		packageIDs := lo.Keys(t.findingsByPackageByLocation[location])
		packages := lo.Map(packageIDs, func(id string, _ int) scan.Package {
			return t.packagesByID[id]
		})

		sort.SliceStable(packages, func(i, j int) bool {
			return packages[i].Name < packages[j].Name
		})

		for _, pkg := range packages {
			line := fmt.Sprintf(
				"%s       📦 %s %s %s",
				verticalLine,
				pkg.Name,
				pkg.Version,
				styleSubtle.Render("("+pkg.Type+")"),
			)
			lines = append(lines, line)

			findings := t.findingsByPackageByLocation[location][pkg.ID]
			sort.SliceStable(findings, func(i, j int) bool {
				return findings[i].Vulnerability.ID < findings[j].Vulnerability.ID
			})

			for i := range findings {
				f := findings[i]
				line := fmt.Sprintf(
					"%s           %s %s%s%s",
					verticalLine,
					renderSeverity(f.Vulnerability.Severity),
					renderVulnerabilityID(f.Vulnerability),
					renderFixedIn(f.Vulnerability),
					renderTriaging(verticalLine, f.TriageAssessments),
				)
				lines = append(lines, line)
			}
		}

		lines = append(lines, verticalLine)
	}

	return strings.Join(lines, "\n")
}

func renderSeverity(severity string) string {
	switch severity {
	case "Negligible":
		return styleNegligible.Render(severity)
	case "Low":
		return styleLow.Render(severity)
	case "Medium":
		return styleMedium.Render(severity)
	case "High":
		return styleHigh.Render(severity)
	case "Critical":
		return styleCritical.Render(severity)
	default:
		return severity
	}
}

func renderVulnerabilityID(vuln scan.Vulnerability) string {
	var cveID string

	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			cveID = alias
			break
		}
	}

	if cveID == "" {
		return hyperlinkVulnerabilityID(vuln.ID)
	}

	return fmt.Sprintf(
		"%s %s",
		hyperlinkVulnerabilityID(cveID),

		styleSubtle.Render(hyperlinkVulnerabilityID(vuln.ID)),
	)
}

var termSupportsHyperlinks = termlink.SupportsHyperlinks()

func hyperlinkVulnerabilityID(id string) string {
	if !termSupportsHyperlinks {
		return id
	}

	switch {
	case strings.HasPrefix(id, "CVE-"):
		return termlink.Link(id, fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", id))

	case strings.HasPrefix(id, "GHSA-"):
		return termlink.Link(id, fmt.Sprintf("https://github.com/advisories/%s", id))
	}

	return id
}

func renderFixedIn(vuln scan.Vulnerability) string {
	if vuln.FixedVersion == "" {
		return ""
	}

	return fmt.Sprintf(" fixed in %s", vuln.FixedVersion)
}

func renderTriaging(verticalLine string, trs []scan.TriageAssessment) string {
	if len(trs) == 0 {
		return ""
	}

	// Only show one line per triage source
	seen := make(map[string]struct{})
	var lines []string
	for _, tr := range trs {
		if _, ok := seen[tr.Source]; ok {
			continue
		}
		seen[tr.Source] = struct{}{}
		lines = append(lines, renderTriageAssessment(verticalLine, tr))
	}

	return "\n" + strings.Join(lines, "\n")
}

func renderTriageAssessment(verticalLine string, tr scan.TriageAssessment) string {
	label := styles.Bold().Render(fmt.Sprintf("%t positive", tr.TruePositive))
	return fmt.Sprintf("%s             ⚖️  %s according to %s", verticalLine, label, tr.Source)
}

var (
	styleSubtle = lipgloss.NewStyle().Foreground(lipgloss.Color("#999999"))

	styleNegligible = lipgloss.NewStyle().Foreground(lipgloss.Color("#999999"))
	styleLow        = lipgloss.NewStyle().Foreground(lipgloss.Color("#00ff00"))
	styleMedium     = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffff00"))
	styleHigh       = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff9900"))
	styleCritical   = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff0000"))
)
