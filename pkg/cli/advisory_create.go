package cli

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/apk/client"
	"github.com/chainguard-dev/clog"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/advisory/prompt"
	buildconfigs "github.com/wolfi-dev/wolfictl/pkg/configs/build"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
	"github.com/wolfi-dev/wolfictl/pkg/yam"
)

func cmdAdvisoryCreate() *cobra.Command { //nolint:gocyclo
	p := &createParams{}
	cmd := &cobra.Command{
		Use:        "create",
		Short:      "Create a new advisory",
		Deprecated: advisoryDeprecationMessage,
		Long: `Create a new advisory.

Use this command to create a new advisory, i.e. when the given
package/vulnerability combination doesn't already exist in the advisories repo.
If the package/vulnerability combination already exists, use the "update"
command instead.

This command will prompt for all required fields, and will attempt to fill in
as many optional fields as possible. You can abort the advisory creation at any
point in the prompt by pressing Ctrl+C.

You can specify required values on the command line using the flags relevant to
the advisory you are creating. If not all required values are provided on the
command line, the command will prompt for the missing values.

If the --no-prompt flag is specified, then the command will fail if any
required fields are missing.

It's possible to create advisories for multiple packages and/or vulnerabilities 
at once by using a comma-separated list of package names and vulnerabilities. 
This is available for both the CLI flags and the interactive prompt fields.

When performing a bulk operation (i.e. on multiple advisories at once), if an
advisory already has an event of the same type as the one being added, that
advisory will be skipped, and a warning will be logged. This is to prevent
adding redundant events to advisories that already have the same type of event.

This command also performs a follow-up operation to discover aliases for the
newly created advisory and any other advisories for the same package.`,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			// Get initial values for distro-related parameters.
			archs := p.archs
			packageRepositoryURL := p.packageRepositoryURL
			distroRepoDir := resolveDistroDir(p.distroRepoDir)
			advisoriesRepoDir := resolveAdvisoriesDirInput(p.advisoriesRepoDir)

			// If we're not using auto-detection, we need to fail fast on any missing
			// parameter values.
			if p.doNotDetectDistro {
				var missingParamWarnings []string

				if distroRepoDir == "" {
					missingParamWarnings = append(missingParamWarnings, fmt.Sprintf("  - distro repository directory (specify using --%s)", flagNameDistroRepoDir))
				}
				if advisoriesRepoDir == "" {
					missingParamWarnings = append(missingParamWarnings, fmt.Sprintf("  - advisories repository directory (specify using --%s)", flagNameAdvisoriesRepoDir))
				}
				if packageRepositoryURL == "" {
					missingParamWarnings = append(missingParamWarnings, fmt.Sprintf("  - package repository URL (specify using --%s)", flagNamePackageRepoURL))
				}
				if len(missingParamWarnings) > 0 {
					return fmt.Errorf(
						"one or more distro configuration values was left unspecified and couldn't be automatically resolved because distro auto-detection was disabled by user:\n%v",
						strings.Join(missingParamWarnings, "\n"),
					)
				}
			}

			// If we made it this far, we either have all the values, or we'll be able to
			// use auto-detection to resolve the rest.

			if distroRepoDir == "" || advisoriesRepoDir == "" || packageRepositoryURL == "" {
				d, err := distro.Detect()
				if err != nil {
					return fmt.Errorf("distro repo dir and/or advisories repo dir was left unspecified, and distro auto-detection failed: %w", err)
				}

				// Replace only the values that are still empty.

				if len(archs) == 0 {
					archs = d.Absolute.SupportedArchitectures
				}

				if packageRepositoryURL == "" {
					packageRepositoryURL = d.Absolute.APKRepositoryURL
				}

				if distroRepoDir == "" {
					distroRepoDir = d.Local.PackagesRepo.Dir
				}

				if advisoriesRepoDir == "" {
					advisoriesRepoDir = d.Local.AdvisoriesRepo.Dir
				}

				_, _ = fmt.Fprint(os.Stderr, renderDetectedDistro(d))
			}

			advGetter := advisory.NewFSGetter(os.DirFS(advisoriesRepoDir))

			encodeOpts, err := yam.TryReadingEncodeOptions(advisoriesRepoDir)
			if err != nil {
				return fmt.Errorf("getting yam encode options: %w", err)
			}
			encoder := advisory.NewYamDocumentEncoder(encodeOpts)
			advPutter := advisory.NewFSPutter(rwos.DirFS(advisoriesRepoDir), encoder)

			fsys := rwos.DirFS(distroRepoDir)
			buildCfgs, err := buildconfigs.NewIndex(ctx, fsys)
			if err != nil {
				return fmt.Errorf("unable to select packages: %w", err)
			}

			reqParams := p.requestParams

			c := client.New(http.DefaultClient)
			var apkindexes []*apk.APKIndex
			for _, arch := range archs {
				idx, err := c.GetRemoteIndex(ctx, packageRepositoryURL, arch)
				if err != nil {
					return fmt.Errorf("getting APKINDEX for %s: %w", arch, err)
				}
				apkindexes = append(apkindexes, idx)
			}

			if missing := reqParams.MissingValues(); len(missing) > 0 {
				clog.FromContext(ctx).Debug("some request parameters are missing", "missing", missing)
				if p.doNotPrompt {
					return fmt.Errorf("missing required fields, and user disabled prompting for missing fields: %v", missing)
				}

				// prompt for missing fields

				allowedPackages := func() ([]string, error) {
					return advGetter.PackageNames(ctx)
				}

				allowedVulnerabilities := func(_ string) ([]string, error) {
					return nil, nil
				}

				allowedFixedVersions := func(packageName string) ([]string, error) {
					return newAllowedFixedVersionsFunc(apkindexes, buildCfgs)(packageName), nil
				}

				m := prompt.New(prompt.Configuration{
					RequestParams:              reqParams,
					AllowedPackagesFunc:        allowedPackages,
					AllowedVulnerabilitiesFunc: allowedVulnerabilities,
					AllowedFixedVersionsFunc:   allowedFixedVersions,
				})
				var returnedModel tea.Model
				program := tea.NewProgram(m)

				if returnedModel, err = program.Run(); err != nil {
					return err
				}

				if m, ok := returnedModel.(prompt.Model); ok {
					if m.EarlyExit {
						if m.Err != nil {
							return m.Err
						}

						return nil
					}

					reqParams = m.RequestParams
				} else {
					return fmt.Errorf("unexpected model type: %T", returnedModel)
				}
			}

			requests, err := reqParams.GenerateRequests()
			if err != nil {
				return fmt.Errorf("generating advisory data requests: %w", err)
			}

			// If there are multiple requests to process, this is a "bulk" operation, and we
			// want to skip (but log a warning) cases where we'd be adding an event to an
			// existing advisory with the same type as that advisory's latest pre-existing
			// event. To make this determination, we'll need a Getter.

			// Default behavior.
			skipRedundantEventType := func(_ advisory.Request) (bool, error) {
				return false, nil
			}

			if len(requests) >= 2 {
				g := advisory.NewFSGetter(os.DirFS(advisoriesRepoDir))

				// Behavior for bulk operation.
				skipRedundantEventType = func(req advisory.Request) (bool, error) {
					return doesRequestRepeatEventType(ctx, g, req)
				}
			}

			// Do just a single pass at finding aliases, instead of per-request.
			af := advisory.NewHTTPAliasFinder(http.DefaultClient)

			for _, r := range requests {
				skip, err := skipRedundantEventType(r)
				if err != nil {
					return fmt.Errorf("checking for redundant event type for package %q: %w", r.Package, err)
				}
				if skip {
					clog.FromContext(ctx).Warn(
						"skipping processing of advisory request with same event type as existing advisory's latest event",
						"package", r.Package,
						"advisoryID", r.AdvisoryID,
						"aliases", r.Aliases,
						"eventType", r.Event.Type,
					)
					continue
				}

				// Complete the alias set for the request. Use the singular AliasFinder to
				// benefit from its cache across multiple requests' resolutions.
				aliases, err := advisory.CompleteAliasSet(ctx, af, r.Aliases)
				if err != nil {
					return fmt.Errorf("completing alias set for advisory request (package %q): %w", r.Package, err)
				}
				r.Aliases = aliases

				_, err = advPutter.Upsert(ctx, r)
				if err != nil {
					return fmt.Errorf("creating advisory data for %q (%v): %w", r.Package, r.Aliases, err)
				}
			}

			return nil
		},
	}

	p.addFlagsTo(cmd)
	return cmd
}

type createParams struct {
	doNotDetectDistro bool
	doNotPrompt       bool

	requestParams                    advisory.RequestParams
	distroRepoDir, advisoriesRepoDir string
	archs                            []string
	packageRepositoryURL             string
}

func (p *createParams) addFlagsTo(cmd *cobra.Command) {
	addNoDistroDetectionFlag(&p.doNotDetectDistro, cmd)
	addNoPromptFlag(&p.doNotPrompt, cmd)

	addFlagsForAdvisoryRequestParams(&p.requestParams, cmd)
	addDistroDirFlag(&p.distroRepoDir, cmd)
	addAdvisoriesDirFlag(&p.advisoriesRepoDir, cmd)
	cmd.Flags().StringSliceVar(&p.archs, "arch", []string{"x86_64", "aarch64"}, "package architectures to find published versions for")
	addPackageRepoURLFlag(&p.packageRepositoryURL, cmd)
}
