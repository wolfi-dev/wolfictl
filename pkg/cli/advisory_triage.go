package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/adrg/xdg"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/db/v5/store"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/go-apk/pkg/expandapk"
	"github.com/chainguard-dev/yam/pkg/yam/formatted"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/cli/styles"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/scan"
	"github.com/wolfi-dev/wolfictl/pkg/scan/target"
	"github.com/wolfi-dev/wolfictl/pkg/scan/triage"
	"github.com/wolfi-dev/wolfictl/pkg/scan/triage/gogitversion"
	"github.com/wolfi-dev/wolfictl/pkg/scan/triage/govulncheck"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/trace"
	"gopkg.in/yaml.v3"
)

//nolint:gocyclo // we should refactor this function when the design is more solid
func cmdAdvisoryTriage() *cobra.Command {
	p := &triageParams{}
	cmd := &cobra.Command{
		Use:   "triage",
		Short: "Triage vulnerabilities and record analysis in advisory data",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			logger := clog.NewLogger(getLogger(p.verbosity))
			ctx = clog.WithLogger(ctx, logger)

			if p.traceFile != "" {
				w, err := os.Create(p.traceFile)
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
						clog.FromContext(ctx).Errorf("shutting down trace provider: %v", err)
					}
				}()

				tctx, span := otel.Tracer("wolfictl").Start(ctx, "advisory triage")
				defer span.End()
				ctx = tctx

				logger.Info("tracing enabled", "traceFile", p.traceFile)
			}

			// TODO: Support triaging multiple packages at once
			if p.packageName == "" {
				return fmt.Errorf("--%s is required", flagNamePackage)
			}

			if p.advisoriesDir == "" {
				return fmt.Errorf("--%s is required", flagNameAdvisoriesRepoDir)
			}

			if p.builtPackagesDir == "" {
				return fmt.Errorf("--%s is required", flagNameBuiltPackagesDir)
			}

			advIndex, err := v2.NewIndex(ctx, rwos.DirFS(p.advisoriesDir))
			if err != nil {
				return fmt.Errorf("creating index of advisories repo: %w", err)
			}

			if advIndex.Select().Len() == 0 {
				return fmt.Errorf("no advisory documents found in %q", p.advisoriesDir)
			}

			o, err := target.New(ctx, os.DirFS(p.builtPackagesDir))
			if err != nil {
				return fmt.Errorf("constructing APK opener: %w", err)
			}

			targetAPK, err := o.LatestVersion(p.packageName)
			if err != nil {
				return fmt.Errorf("getting latest version of %q: %w", p.packageName, err)
			}

			apk, err := o.Open(targetAPK)
			if err != nil {
				return fmt.Errorf("opening APK file for %q: %w", targetAPK, err)
			}
			defer apk.Close()

			expandedAPKTempDir, err := os.MkdirTemp("", "wolfictl-expanded-apk-*")
			if err != nil {
				return fmt.Errorf("creating temporary directory for expanded APK: %w", err)
			}
			defer os.RemoveAll(expandedAPKTempDir)
			apkExpanded, err := expandapk.ExpandApk(ctx, apk, expandedAPKTempDir)
			if err != nil {
				return fmt.Errorf("expanding APK: %w", err)
			}

			// For now, the implementation peeks into the Grype database. But it'd be good
			// to replace this with a more upstream way to get the vulnerability data, such
			// as local OSV data stores.
			grypeStore, err := store.New(filepath.Join(scan.GrypeDBDir(), "5", "vulnerability.db"), false)
			if err != nil {
				return fmt.Errorf("creating grype vulnerability data store: %w", err)
			}
			grypeVulnProvider, err := db.NewVulnerabilityProvider(grypeStore)
			if err != nil {
				return fmt.Errorf("creating grype vulnerability provider: %w", err)
			}
			defer grypeStore.Close()

			// TODO: Make this list and its order configurable by the user
			var triagers []triage.Triager
			triagers = append(triagers,
				gogitversion.New(gogitversion.TriagerOptions{
					RepositoriesCacheDir:       p.upstreamRepoCacheDir,
					GrypeVulnerabilityProvider: grypeVulnProvider,
				}),
				govulncheck.New(apkExpanded.TarFS),
			)

			// do APK scan
			scanner, err := scan.NewScanner(ctx, "", false)
			if err != nil {
				return fmt.Errorf("creating scanner: %w", err)
			}

			targetAPKFile, err := o.Open(targetAPK)
			if err != nil {
				return fmt.Errorf("opening APK file for %q: %w", targetAPK, err)
			}

			result, err := scanner.ScanAPK(ctx, targetAPKFile, p.distroDir)
			if err != nil {
				return fmt.Errorf("scanning APK %q: %w", targetAPK, err)
			}

			targetAPKFile.Close()

			// filter results, so we only triage the findings that are not already resolved
			filteredFindings, err := scan.FilterWithAdvisories(ctx, *result, advIndex, scan.AdvisoriesSetResolved)
			if err != nil {
				return fmt.Errorf("filtering findings with advisories: %w", err)
			}
			result.Findings = filteredFindings

			requests, err := triage.Do(ctx, triagers, result)
			if err != nil {
				return fmt.Errorf("triaging vulnerability scan results for %v: %w", targetAPK, err)
			}

			af := advisory.NewHTTPAliasFinder(http.DefaultClient)
			var dryRunWriter io.Writer = os.Stdout

			if p.dryRun {
				fmt.Fprintln(dryRunWriter) // for visual separation
			}

			for _, req := range requests {
				req, err := req.ResolveAliases(ctx, af)
				if err != nil {
					return fmt.Errorf("resolving aliases for %s: %w", req.VulnerabilityID, err)
				}

				if err := req.Validate(); err != nil {
					return fmt.Errorf(
						"invalid advisory data request for %s in %s: %w",
						req.VulnerabilityID,
						req.Package,
						err,
					)
				}

				if p.dryRun {
					vuln := req.VulnerabilityID
					for _, alias := range req.Aliases {
						vuln += fmt.Sprintf(" / %s", alias)
					}

					_, err := fmt.Fprintf(
						dryRunWriter,
						"%s: %s (DRY RUN)\n",
						styles.Bold().Render(req.Package),
						styles.Bold().Render(vuln),
					)
					if err != nil {
						return fmt.Errorf("writing advisory data request to stdout: %w", err)
					}

					// TODO: We can skip the upfront yaml.Node encoding once yam supports non-node encoding directly.
					n := new(yaml.Node)
					err = n.Encode(req.Event)
					if err != nil {
						return fmt.Errorf("marshaling advisory event: %w", err)
					}
					err = formatted.NewEncoder(dryRunWriter).Encode(n)
					if err != nil {
						return fmt.Errorf("writing advisory event to stdout: %w", err)
					}

					fmt.Fprintln(dryRunWriter) // for visual separation
					continue
				}

				doc, err := advIndex.Select().WhereName(req.Package).First()
				if err != nil {
					return err
				}
				if _, exists := doc.Configuration().Advisories.Get(req.VulnerabilityID); !exists {
					err := advisory.Create(ctx, *req, advisory.CreateOptions{
						AdvisoryDocs: advIndex,
					})
					if err != nil {
						return fmt.Errorf("creating advisory: %w", err)
					}
				} else {
					err = advisory.Update(ctx, *req, advisory.UpdateOptions{
						AdvisoryDocs: advIndex,
					})
					if err != nil {
						return fmt.Errorf("updating advisory data: %w", err)
					}
				}

				logger.Info("advisory data updated", "package", req.Package, "vulnerability", req.VulnerabilityID, "eventType", req.Event.Type)
			}

			logger.Info("triaging complete", "newAdvisoryEventsCount", len(requests), "targetAPK", targetAPK)

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type triageParams struct {
	verbosity            int
	builtPackagesDir     string
	advisoriesDir        string
	distroDir            string
	upstreamRepoCacheDir string
	packageName          string
	traceFile            string
	dryRun               bool
}

func (p *triageParams) addFlagsTo(cmd *cobra.Command) {
	addVerboseFlag(&p.verbosity, cmd)
	addBuiltPackagesDirFlag(&p.builtPackagesDir, cmd)
	addAdvisoriesDirFlag(&p.advisoriesDir, cmd)
	addDistroDirFlag(&p.distroDir, cmd)
	addPackageFlag(&p.packageName, cmd)
	cmd.Flags().StringVar(&p.traceFile, flagNameTraceFile, "", "write trace data to file")
	cmd.Flags().StringVarP(&p.upstreamRepoCacheDir, flagNameUpstreamRepositoryCacheDir, "c", gitRepositoriesCacheDir, "location for caching upstream project git repositories")
	cmd.Flags().BoolVar(&p.dryRun, "dry-run", false, "don't actually update advisory data, just print the data that would be added")
}

const flagNameUpstreamRepositoryCacheDir = "upstream-repository-cache-dir"
const flagNameTraceFile = "trace"

var gitRepositoriesCacheDir = filepath.Join(xdg.CacheHome, "wolfictl", "advisory", "triage", "git")
