package cli

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	goapk "chainguard.dev/apko/pkg/apk/apk"
	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/apk"
	"github.com/wolfi-dev/wolfictl/pkg/cli/styles"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/scan"
	"github.com/wolfi-dev/wolfictl/pkg/versions"
)

func cmdAdvisoryValidateFixes() *cobra.Command {
	p := &validateFixesParams{}
	cmd := &cobra.Command{
		Use:           "fixes",
		Short:         "Validate fixes recorded in advisories",
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			logger := clog.NewLogger(newLogger(p.verbosity))
			ctx := clog.WithLogger(cmd.Context(), logger)

			if p.advisoriesRepoDir == "" {
				return fmt.Errorf("need --%s", flagNameAdvisoriesRepoDir)
			}

			if p.builtPackagesDir == "" {
				return fmt.Errorf("need --%s", flagNameBuiltPackagesDir)
			}

			advIndex, err := v2.NewIndex(ctx, rwos.DirFS(p.advisoriesRepoDir))
			if err != nil {
				return fmt.Errorf("creating index of advisories repo: %w", err)
			}

			if advIndex.Select().Len() == 0 {
				return fmt.Errorf("no advisory documents found in %q", p.advisoriesRepoDir)
			}

			fsys := os.DirFS(p.builtPackagesDir)

			// Look through the built packages fsys, recursively?, filter out non-APK files
			// For each APK
			// 	- parse it to find its APK package name
			// 	- look up its advisories -> get all advisories where last event's type is "fixed"
			//	- scan the APK
			//	- surface any overlap of {vuln shows up from scan} and {vuln is said to be fixed in our advisories}

			pathsToAPKs, err := findPathsOfAPKs(fsys)
			if err != nil {
				return fmt.Errorf("finding paths of APKs: %w", err)
			}

			if len(pathsToAPKs) == 0 {
				return fmt.Errorf("no APKs found in %q", p.builtPackagesDir)
			}

			logger.Debug("found APKs to check", "count", len(pathsToAPKs))

			var invalidFixedAdvisories []invalidFixedAdvisory
			for _, path := range pathsToAPKs {
				invalidFixes, err := findInvalidFixedAdvisoriesForAPK(ctx, fsys, path, advIndex, p.distro)
				if err != nil {
					return fmt.Errorf("validating fixed advisories for APK %q: %w", path, err)
				}
				invalidFixedAdvisories = append(invalidFixedAdvisories, invalidFixes...)
			}

			if len(invalidFixedAdvisories) > 0 {
				for _, inv := range invalidFixedAdvisories { //nolint:gocritic
					fmt.Printf(
						"❌  %s: %s does not fix %s: found %s @ %s in %s\n",
						styles.Bold().Render(inv.pkginfo.Name),
						styles.Bold().Render(inv.pkginfo.Version),
						styles.Bold().Render(inv.advisory.ID),
						inv.finding.Package.Name,
						inv.finding.Package.Version,
						inv.finding.Package.Location,
					)
				}

				fmt.Println() // for separation

				return fmt.Errorf("invalid fixed advisories found")
			}

			logger.Info("no invalid fixed advisories found")

			return nil
		},
	}

	p.addFlagsToCommand(cmd)
	return cmd
}

type validateFixesParams struct {
	advisoriesRepoDir string
	builtPackagesDir  string
	verbosity         int
	distro            string
}

func (p *validateFixesParams) addFlagsToCommand(cmd *cobra.Command) {
	addAdvisoriesDirFlag(&p.advisoriesRepoDir, cmd)
	addVerboseFlag(&p.verbosity, cmd)

	cmd.Flags().StringVarP(&p.builtPackagesDir, flagNameBuiltPackagesDir, "b", "", "directory containing built packages")
	cmd.Flags().StringVar(&p.distro, "distro", "wolfi", "distro to use during vulnerability matching")
}

const flagNameBuiltPackagesDir = "built-packages-dir"

func findPathsOfAPKs(fsys fs.FS) ([]string, error) {
	var pathsToAPKs []string
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// TODO: consider a recursive option
		if d.IsDir() && path != "." {
			return fs.SkipDir
		}

		if !d.Type().IsRegular() {
			return nil
		}

		// if extension isn't apk, skip
		if filepath.Ext(path) != ".apk" {
			return nil
		}

		pathsToAPKs = append(pathsToAPKs, path)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return pathsToAPKs, nil
}

type invalidFixedAdvisory struct {
	pkginfo  goapk.Package
	advisory v2.Advisory
	finding  scan.Finding
}

func findInvalidFixedAdvisoriesForAPK(
	ctx context.Context,
	fsys fs.FS,
	path string,
	advIndex *configs.Index[v2.Document],
	distro string,
) ([]invalidFixedAdvisory, error) {
	logger := clog.FromContext(ctx)

	logger.Debug("validating fixed advisories for APK", "path", path)

	f, err := fsys.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening APK file %q: %w", path, err)
	}
	pkginfoRef, err := apk.PKGINFOFromAPK(f)
	if err != nil {
		return nil, fmt.Errorf("parsing APK file %q: %w", path, err)
	}
	pkginfo := *pkginfoRef

	pkgName := pkginfo.Name

	// Get advisories for this package
	docs := advIndex.Select().WhereName(pkgName).Configurations()
	if len(docs) == 0 {
		logger.Warn("no advisories found for package, skipping vulnerability scan", "package", pkgName)
		return nil, nil
	}
	if len(docs) > 1 {
		return nil, fmt.Errorf("multiple advisory documents found for single package %q", pkgName)
	}
	doc := docs[0]

	// Get the "fixed" advisories for this package
	var fixedAdvisories []v2.Advisory
	for _, adv := range doc.Advisories {
		if adv.Latest().Type == v2.EventTypeFixed {
			fixedAdvisories = append(fixedAdvisories, adv)
		}
	}

	if len(fixedAdvisories) == 0 {
		logger.Warn("no fixed advisories found for package, skipping vulnerability scan", "package", pkgName)
		return nil, nil
	}

	// Scan the APK
	scanner, err := scan.NewScanner("", false)
	if err != nil {
		return nil, fmt.Errorf("creating scanner: %w", err)
	}

	// TODO: Scanning needs a better interface, this is a hack to seek to the start of the file.
	//  Consider using io.ReaderAt.
	if seeker, ok := f.(io.Seeker); ok {
		_, err = seeker.Seek(0, io.SeekStart)
		if err != nil {
			return nil, fmt.Errorf("seeking to start of APK file: %w", err)
		}
	} else {
		logger.Warn("unable to seek to start of APK file, scanning may fail")
	}

	result, err := scanner.ScanAPK(ctx, f, distro)
	if err != nil {
		return nil, fmt.Errorf("scanning APK %q: %w", path, err)
	}

	var invalidFixedAdvisories []invalidFixedAdvisory

	// Compare the scan results with the advisories
	for _, finding := range result.Findings { //nolint:gocritic
		vuln := finding.Vulnerability
		foundVulnIDs := make(map[string]struct{})
		foundVulnIDs[vuln.ID] = struct{}{}
		for _, alias := range vuln.Aliases {
			foundVulnIDs[alias] = struct{}{}
		}

		observedWrongAdvisoryVulnIDs := make(map[string]struct{})

		for _, adv := range fixedAdvisories {
			fixedVulnIDs := append([]string{adv.ID}, adv.Aliases...)
			for _, fixedVulnID := range fixedVulnIDs {
				if _, ok := observedWrongAdvisoryVulnIDs[fixedVulnID]; ok {
					logger.Debug("already observed wrong advisory for this vulnerability, skipping this time", "package", pkgName, "advisory", adv.ID)
					continue
				}

				if _, ok := foundVulnIDs[fixedVulnID]; ok {
					fixedAdv, ok := adv.Latest().Data.(v2.Fixed)
					if !ok {
						logger.Warn("fixed advisory does not have fixed data, skipping", "package", pkgName, "advisory", adv.ID)
						continue
					}

					fixedVersion, err := versions.NewVersion(fixedAdv.FixedVersion)
					if err != nil {
						return nil, fmt.Errorf("parsing fixed version %q: %w", fixedAdv.FixedVersion, err)
					}
					foundVersion, err := versions.NewVersion(pkginfo.Version)
					if err != nil {
						return nil, fmt.Errorf("parsing found version %q: %w", finding.Package.Version, err)
					}

					if foundVersion.GreaterThanOrEqual(fixedVersion) {
						for _, id := range fixedVulnIDs {
							observedWrongAdvisoryVulnIDs[id] = struct{}{}
						}

						// The advisory says this APK version should've been fixed for this vulnerability.
						invalidFixedAdvisories = append(invalidFixedAdvisories, invalidFixedAdvisory{
							pkginfo:  pkginfo,
							advisory: adv,
							finding:  finding,
						})
					}
				}
			}
		}
	}

	return invalidFixedAdvisories, nil
}
