package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/chainguard-dev/clog"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cli/browser"
	"github.com/dustin/go-humanize"
	"github.com/google/go-github/v58/github"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/advisory"
	"github.com/wolfi-dev/wolfictl/pkg/advisory/question"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/ctrlcwrapper"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/interview"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/keytocontinue"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/picker"
	"github.com/wolfi-dev/wolfictl/pkg/cli/internal/builds"
	"github.com/wolfi-dev/wolfictl/pkg/cli/internal/wrapped"
	"github.com/wolfi-dev/wolfictl/pkg/cli/styles"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
	"github.com/wolfi-dev/wolfictl/pkg/internal"
	question2 "github.com/wolfi-dev/wolfictl/pkg/question"
	"github.com/wolfi-dev/wolfictl/pkg/scan"
	"github.com/wolfi-dev/wolfictl/pkg/vuln"
)

//nolint:gocyclo
func cmdAdvisoryGuide() *cobra.Command {
	opts := &advisoryGuideParams{}

	cmd := &cobra.Command{
		Use:           "guide",
		Short:         "Launch an interactive guide to help you enter advisory data for a package",
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			// Construct some things we'll need later.

			githubClient := github.NewClient(nil).WithAuthToken(os.Getenv("GITHUB_TOKEN"))
			af := advisory.NewHTTPAliasFinder(http.DefaultClient)

			// Begin the guide!

			if !opts.speedy {
				fmt.Println()
				wrapped.Println(welcomeMessage)
				fmt.Println(sectionDivider)
				fmt.Println()

				model, err := tea.NewProgram(
					ctrlcwrapper.New(
						keytocontinue.New(
							"enter",
							"to find the package(s) you've just built...",
						),
					),
				).Run()
				if err != nil {
					return fmt.Errorf("running key_to_continue: %w", err)
				}
				if m, ok := model.(ctrlcwrapper.Any); ok {
					if m.UserWantsToExit() {
						return nil
					}
				}
			}

			// Step: Let's get oriented to your distro/repo setup.

			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("failed to get current working directory: %w", err)
			}

			detected, err := distro.DetectFromDirV2(cwd)
			if err != nil {
				if errors.Is(err, distro.ErrNotPackagesRepo) {
					wrapped.Fatal(errorForNotADistroDirectory(cwd))
				}

				return fmt.Errorf("failed to detect distro: %w", err)
			}

			wrapped.Println(fmt.Sprintf(
				"It looks like you're working in %s.",
				styles.Bold().Render(detected.Absolute.Name),
			))
			fmt.Println()

			opts.pause()

			// Step: Select your package

			packagesDir := filepath.Join(detected.Local.PackagesRepo.Dir, "packages")

			wrapped.Println(fmt.Sprintf(
				"We'll look in %s to see what packages you've built so far.",
				styles.Bold().Render(packagesDir),
			))
			fmt.Println()

			opts.pause()

			fsys := os.DirFS(packagesDir)
			buildMap, err := builds.Find(fsys, detected.Absolute.SupportedArchitectures)
			if err != nil {
				return fmt.Errorf("failed to find builds: %w", err)
			}

			wrapped.Println("These are your most recent builds. Which of these would you like to work on right now?")
			fmt.Println()

			buildGroups := lo.Values(buildMap)

			// Sort by most recently built
			sort.Slice(buildGroups, func(i, j int) bool {
				return buildGroups[i].Origin.FileInfo.ModTime().After(buildGroups[j].Origin.FileInfo.ModTime())
			})

			// Look at only the 5 latest builds
			if len(buildGroups) > 5 {
				buildGroups = buildGroups[:5]
			}

			bgPickerOpts := picker.Options[builds.BuildGroup]{
				Items:               buildGroups,
				MessageForZeroItems: "No builds found",
				ItemRenderFunc:      renderBuildGroup,
			}
			bgPicker := picker.New(bgPickerOpts)
			bgPickerTea, err := tea.NewProgram(ctrlcwrapper.New(bgPicker)).Run()
			if err != nil {
				return fmt.Errorf("running picker for build groups: %w", err)
			}
			if bgPickerCtrlC, ok := bgPickerTea.(ctrlcwrapper.Model[picker.Model[builds.BuildGroup]]); ok {
				if bgPickerCtrlC.UserWantsToExit() {
					return nil
				}

				bgPicker = bgPickerCtrlC.Unwrap()
			}
			bg := bgPicker.Picked()

			if !opts.speedy {
				wrapped.Println(fmt.Sprintf("Cool! We'll focus on %s.\n", styles.Bold().Render(bg.Origin.PkgInfo.Name)))
			}

			opts.pause()

			fmt.Println(sectionDivider)
			fmt.Println()

			if !opts.speedy {
				wrapped.Println(fmt.Sprintf(
					"Filing advisory data is necessary %s there are vulnerabilities in the APKs you've built that don't already have the advisory data they need.\n",
					styleBoldItalic.Render("if and only if"),
				))

				opts.pause()

				wrapped.Println("So, to see how much work we have to do, we'll scan your APK file(s) for vulnerabilities, and we'll filter out the vulnerabilities that already have the advisory data they need.\n")
			}

			// Scan all APK builds from the build group!

			distroID := strings.ToLower(detected.Absolute.Name)

			scanner, err := scan.NewScanner(scan.DefaultOptions)
			if err != nil {
				return fmt.Errorf("failed to create vulnerability scanner: %w", err)
			}
			defer scanner.Close()

			// We don't want logging, it's unnecessary and interrupts the flow of the guide.
			ctx = clog.WithLogger(ctx, clog.NewLogger(internal.NopLogger()))

			results, err := bg.Scan(ctx, scanner, distroID)
			if err != nil {
				return fmt.Errorf("failed to scan build group: %w", err)
			}
			collated := collateVulnerabilities(results)

			// Grab the latest advisory data in a new session.

			sess, err := advisory.NewDataSession(
				ctx,
				advisory.DataSessionOptions{
					Distro:       detected,
					GitHubClient: githubClient,
				},
			)
			if err != nil {
				return fmt.Errorf("initializing advisory data session: %w", err)
			}
			defer sess.Close()

			// Important! If there are no vulns from the get-go, exit with a happy message and don't run any pickers.
			triagingHasBegun := false

			// Continue to look for unaddressed vulnerabilities until there are none left
			// (or the user quits early).

			for {
				filtered, err := filterCollatedVulnerabilities(ctx, collated, sess)
				if err != nil {
					return fmt.Errorf("filtering APK findings with advisories: %w", err)
				}

				if len(filtered) == 0 && !triagingHasBegun {
					wrapped.Println("🎉 No vulnerabilities found that need advisory data. You're all set!\n")
					return nil
				}
				triagingHasBegun = true

				sort.Slice(filtered, func(i, j int) bool {
					return filtered[i].Result.Findings[0].Vulnerability.ID < filtered[j].Result.Findings[0].Vulnerability.ID
				})

				// Let the user pick a package vulnerability match to focus on.

				wrapped.Println("Remaining vulnerabilities:\n")

				var actions []picker.CustomAction[resultWithAPKs]
				if len(filtered) > 0 {
					actions = append(actions, customActionBrowser)
				}
				if sess.Modified() {
					actions = append(actions, newCustomActionPR(ctx, sess))
				}

				vaPickerOpts := picker.Options[resultWithAPKs]{
					Items:               filtered,
					MessageForZeroItems: "✅ No vulnerabilities left. Let's open a PR!",
					ItemRenderFunc:      renderResultWithAPKs,
					CustomActions:       actions,
				}
				vaPicker := picker.New(vaPickerOpts)
				vaPickerTea, err := tea.NewProgram(ctrlcwrapper.New(vaPicker)).Run()
				if err != nil {
					return fmt.Errorf("running picker for vulnerabilities: %w", err)
				}
				if vaPickerCtrlC, ok := vaPickerTea.(ctrlcwrapper.Model[picker.Model[resultWithAPKs]]); ok {
					if vaPickerCtrlC.UserWantsToExit() {
						return nil
					}

					vaPicker = vaPickerCtrlC.Unwrap()
				}
				if vaPicker.Error != nil {
					return fmt.Errorf("vulnerability picker error: %w", vaPicker.Error)
				}

				vaPicked := vaPicker.Picked()
				if vaPicked == nil {
					// The user selected a custom action that quit the picker. Nothing was picked.
					return nil
				}

				// Interview the user about the selected vulnerability match to derive an
				// advisory request.

				findingVulnID := vaPicked.Result.Findings[0].Vulnerability.ID
				req := advisory.Request{
					Package: vaPicked.APKs[0],
				}
				if vuln.RegexCGA.MatchString(findingVulnID) {
					req.AdvisoryID = findingVulnID
				} else {
					req.Aliases = []string{findingVulnID}
				}

				resolvedReq, err := req.ResolveAliases(ctx, af)
				if err != nil {
					clog.FromContext(ctx).Warnf("resolving aliases for advisory request: %v", err)
				}
				req = *resolvedReq

				iv, err := interview.New(question.IsFalsePositive, req)
				if err != nil {
					return fmt.Errorf("creating interview for advisory request: %w", err)
				}
				ivTea, err := tea.NewProgram(ctrlcwrapper.New(iv)).Run()
				if err != nil {
					return fmt.Errorf("running interview for advisory request: %w", err)
				}
				if ivCtrlC, ok := ivTea.(ctrlcwrapper.Model[interview.Model[advisory.Request]]); ok {
					if ivCtrlC.UserWantsToExit() {
						return nil
					}

					iv = ivCtrlC.Unwrap()
				}

				req, err = iv.State()
				if err != nil {
					if errors.Is(err, question2.ErrTerminate) {
						// No advisory data was entered for this vulnerability. Back to the list!
						wrapped.Println("👀 Let's come back to that one later.\n")
						continue
					}

					return fmt.Errorf("getting data back from interview: %w", err)
				}
				if len(req.Aliases) == 0 {
					return fmt.Errorf("no aliases found for advisory request, please report this")
				}

				err = sess.Append(ctx, req)
				if err != nil {
					return fmt.Errorf("adding advisory data: %w", err)
				}

				vuln := req.Aliases[0]
				if len(req.Aliases) > 1 {
					vuln += fmt.Sprintf(" (%s)", strings.Join(req.Aliases[1:], ", "))
				}

				wrapped.Println(fmt.Sprintf(
					"🙌 Nice! We've marked %s in %s as %s.\n",
					styles.Bold().Render(vuln),
					styles.Bold().Render(req.Package),
					styles.Bold().Render(humanizeAdvisoryEventType(req.Event.Type)),
				))
			}
		},
	}

	cmd.AddCommand(
		cmdAdvisoryGuideGraph(),
	)

	opts.addToCmd(cmd)
	return cmd
}

func humanizeAdvisoryEventType(typ string) string {
	switch typ {
	case v2.EventTypeFalsePositiveDetermination:
		return "a false positive"

	case v2.EventTypeTruePositiveDetermination:
		return "a true positive"

	case v2.EventTypeAnalysisNotPlanned:
		return "analysis not planned"

	case v2.EventTypeFixNotPlanned:
		return "fix not planned"

	case v2.EventTypeFixed:
		return "fixed"
	}

	return typ
}

var (
	customActionBrowser = picker.CustomAction[resultWithAPKs]{
		Key:         "b",
		Description: "to see the vulnerability in a web browser",
		Do: func(selected resultWithAPKs) tea.Cmd {
			id := selected.Result.Findings[0].Vulnerability.ID
			u := vuln.URL(id)
			_ = browser.OpenURL(u) //nolint:errcheck
			return nil
		},
	}

	newCustomActionPR = func(ctx context.Context, sess *advisory.DataSession) picker.CustomAction[resultWithAPKs] {
		return picker.CustomAction[resultWithAPKs]{
			Key:         "p",
			Description: "to open a PR with your updates",
			Do: func(_ resultWithAPKs) tea.Cmd {
				err := sess.Push(ctx)
				if err != nil {
					return picker.ErrCmd(fmt.Errorf("data session push: %w", err))
				}

				pr, err := sess.OpenPullRequest(ctx)
				if err != nil {
					return picker.ErrCmd(fmt.Errorf("data session pull request: %w", err))
				}

				_ = browser.OpenURL(pr.URL) //nolint:errcheck
				return tea.Quit
			},
		}
	}
)

type advisoryGuideParams struct {
	speedy bool
}

func (p *advisoryGuideParams) addToCmd(cmd *cobra.Command) {
	cmd.Flags().BoolVarP(&p.speedy, "speedy", "s", false, "Skip explanations and unnecessary time delays")
}

func (p advisoryGuideParams) pause() {
	if !p.speedy {
		time.Sleep(1200 * time.Millisecond)
	}
}

// resultWithAPKs holds a scan result with a single finding and a list of the
// APK names affected by the vulnerability.
type resultWithAPKs struct {
	Result scan.Result
	APKs   []string
}

func renderResultWithAPKs(r resultWithAPKs) string {
	finding := r.Result.Findings[0]
	return fmt.Sprintf(
		"%s (%s) %s @ %s (%d APKs)",
		finding.Vulnerability.ID,
		finding.Package.Type,
		finding.Package.Name,
		finding.Package.Version,
		len(r.APKs),
	)
}

// collateVulnerabilities takes a slice of scan.Result and returns a slice of
// resultWithAPKs.
func collateVulnerabilities(results []scan.Result) []resultWithAPKs {
	vulnAPKsMap := make(map[string]resultWithAPKs)

	for _, result := range results {
		for _, finding := range result.Findings { //nolint:gocritic
			match, exists := vulnAPKsMap[finding.Vulnerability.ID]
			if !exists {
				match = resultWithAPKs{
					Result: scan.Result{
						TargetAPK: result.TargetAPK,
						Findings:  []scan.Finding{finding},
					},
					APKs: []string{},
				}
			}
			match.APKs = append(match.APKs, result.TargetAPK.Name)
			vulnAPKsMap[finding.Vulnerability.ID] = match
		}
	}

	var vulnAPKs []resultWithAPKs
	for _, v := range vulnAPKsMap {
		vulnAPKs = append(vulnAPKs, v)
	}

	return vulnAPKs
}

func filterCollatedVulnerabilities(ctx context.Context, apkResults []resultWithAPKs, sess *advisory.DataSession) ([]resultWithAPKs, error) {
	var filtered []resultWithAPKs

	for _, ar := range apkResults {
		filteredFindings, err := scan.FilterWithAdvisories(
			ctx,
			ar.Result,
			sess.Index(),
			scan.AdvisoriesSetConcluded,
		)
		if err != nil {
			return nil, fmt.Errorf("filtering result findings with advisories: %w", err)
		}

		if len(filteredFindings) == 0 {
			continue
		}

		filteredResult := resultWithAPKs{
			Result: scan.Result{
				TargetAPK: ar.Result.TargetAPK,
				Findings:  filteredFindings,
			},
			APKs: ar.APKs,
		}

		filtered = append(filtered, filteredResult)
	}

	return filtered, nil
}

func renderBuildGroup(bg builds.BuildGroup) string {
	var subpackages string

	if count := len(bg.Subpackages); count == 1 {
		subpackages = fmt.Sprintf(
			" (and %d subpackage)",
			count,
		)
	} else if count > 1 {
		subpackages = fmt.Sprintf(
			" (and %d subpackages)",
			count,
		)
	}

	return fmt.Sprintf(
		"%s %s%s %s",
		bg.Origin.PkgInfo.Name,
		bg.Origin.PkgInfo.Version,
		subpackages,
		styles.Faint().Render(humanize.Time(bg.Origin.FileInfo.ModTime())),
	)
}

const (
	welcomeMessageFormat = `Hi there!

This is wolfictl's interactive guide for advisory data entry.

Advisory data tells us about which vulnerabilities we've seen scanners match to our distro's packages. It's where we record our analysis of these vulnerabilities and whether or not they apply to our packages. It also keeps track of our efforts to fix vulnerabilities in our packages.

It's important that we have advisory data for any package vulnerabilities that have been surfaced by supported vulnerability scanners.

This guide will help you file any missing advisory data for the packages you've just built.

You can exit any time by pressing %s.
`

	notADistroDirectoryMessageFormat = `Apologies! This guide is meant to be run at the root of your local clone of the distro git repo. You're running it from %s right now.

If you know where your distro clone is on your filesystem, cd to that location and try this command again.

Or, if this directory %s your clone of the distro repo, then please go yell at the wolfictl maintainers and demand some answers!
`
)

var (
	sectionDivider = wrapped.Repeat("—")

	welcomeMessage = func() string {
		return fmt.Sprintf(welcomeMessageFormat, styles.Bold().Render("ctrl+C"))
	}()

	errorForNotADistroDirectory = func(cwd string) string {
		return fmt.Sprintf(
			notADistroDirectoryMessageFormat,
			styles.Bold().Render(cwd),
			styles.Bold().Italic(true).Render("is"),
		)
	}

	styleBoldItalic = lipgloss.NewStyle().Bold(true).Italic(true)
)
