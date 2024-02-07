package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/dustin/go-humanize"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/ctrlcwrapper"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/keytocontinue"
	"github.com/wolfi-dev/wolfictl/pkg/cli/components/picker"
	"github.com/wolfi-dev/wolfictl/pkg/cli/internal/builds"
	"github.com/wolfi-dev/wolfictl/pkg/cli/internal/wrapped"
	"github.com/wolfi-dev/wolfictl/pkg/configs"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"github.com/wolfi-dev/wolfictl/pkg/distro"
	"github.com/wolfi-dev/wolfictl/pkg/scan"
)

func cmdAdvisoryGuide() *cobra.Command {
	opts := &advisoryGuideParams{}

	cmd := &cobra.Command{
		Use:           "guide",
		Short:         "Launch an interactive guide to help you enter advisory data for a package",
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

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
					return fmt.Errorf("failed to run key_to_continue program: %w", err)
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

			detected, err := distro.DetectFromDir(cwd)
			if err != nil {
				if errors.Is(err, distro.ErrNotDistroRepo) {
					wrapped.Fatal(errorForNotADistroDirectory(cwd))
				}

				// TODO: handle other cases, such as: this is the distro dir but there's no advisories clone for it

				return fmt.Errorf("failed to detect distro: %w", err)
			}

			wrapped.Println(fmt.Sprintf(
				"It looks like you're working in the %s distro.",
				styleBold.Render(detected.Absolute.Name),
			))
			fmt.Println()

			opts.pause()

			// Step: Select your package

			packagesDir := filepath.Join(detected.Local.PackagesRepo.Dir, "packages")

			wrapped.Println(fmt.Sprintf(
				"We'll look in %s to see what packages you've built so far.",
				styleBold.Render(packagesDir),
			))
			fmt.Println()

			opts.pause()

			fsys := os.DirFS(packagesDir)

			buildMap, err := builds.Find(fsys, detected.Absolute.SupportedArchitectures)
			if err != nil {
				// TODO: make this a user friendly error!
				return fmt.Errorf("failed to find builds: %w", err)
			}

			wrapped.Println("These are your most recent builds. Which of these would you like to work on right now?")
			fmt.Println()

			buildGroups := lo.Values(buildMap)

			// Sort by most recently built
			sort.Slice(buildGroups, func(i, j int) bool {
				return buildGroups[i].Origin.FileInfo.ModTime().After(buildGroups[j].Origin.FileInfo.ModTime())
			})

			// Take at most the 5 latest
			if len(buildGroups) > 5 {
				buildGroups = buildGroups[:5]
			}

			p := picker.New(buildGroups, renderBuildGroup)

			model, err := tea.NewProgram(ctrlcwrapper.New(p)).Run()
			if err != nil {
				return fmt.Errorf("failed to run picker for build groups: %w", err)
			}
			if m, ok := model.(ctrlcwrapper.Model[picker.Model[builds.BuildGroup]]); ok {
				if m.UserWantsToExit() {
					return nil
				}

				p = m.Unwrap()
			}

			bg := p.Picked

			wrapped.Println(fmt.Sprintf("Cool! We'll focus on %s.\n", styleBold.Render(bg.Origin.PkgInfo.Name)))

			opts.pause()

			fmt.Println(sectionDivider)
			fmt.Println()

			// Step: Scan packages for vulnerabilities

			// TODO: Show the user the equivalent `wolfictl scan ...` command to run if they're curious about isolating this step

			// TODO: factor out this message
			wrapped.Println(fmt.Sprintf(
				"Filing advisory data is necessary %s there are vulnerabilities in the APKs you've built that don't already have the advisory data they need.\n",
				styleBoldItalic.Render("if and only if"),
			))

			opts.pause()

			wrapped.Println("So, to see how much work we have to do, we'll scan your APK file(s) for vulnerabilities.\n")

			distroID := strings.ToLower(detected.Absolute.Name)

			scanner, err := scan.NewScanner("", false)
			if err != nil {
				return fmt.Errorf("failed to create vulnerability scanner: %w", err)
			}

			apkfile, err := fsys.Open(bg.Origin.FsysPath)
			if err != nil {
				return fmt.Errorf("failed to open APK file: %w", err)
			}

			// TODO: insert animation for scanning

			// TODO: figure out how to ensure the local advisory data is up to date

			advisoryFsys := rwos.DirFS(detected.Local.AdvisoriesRepo.Dir)
			index, err := v2.NewIndex(ctx, advisoryFsys)
			if err != nil {
				return fmt.Errorf("failed to create advisory index: %w", err)
			}

			result, err := scanner.ScanAPK(ctx, apkfile, distroID)
			if err != nil {
				return fmt.Errorf("failed to scan APK: %w", err)
			}

			// TODO: scan the rest of the build group, too!

			remainingFindings, err := scan.FilterWithAdvisories(*result, []*configs.Index[v2.Document]{index}, scan.AdvisoriesSetResolved)
			if err != nil {
				return err
			}

			countRemainingFindings := len(remainingFindings)
			if countRemainingFindings == 0 {
				wrapped.Println(fmt.Sprintf(
					"Great news! We didn't find any vulnerabilities in %s that don't already have resolutions in the advisory data.\n",
					styleBold.Render(bg.Origin.PkgInfo.Name),
				))

				opts.pause()

				wrapped.Println("You're all done with this package! 🎉\n")

				return nil
			}

			vulnNoun := "vulnerability"
			vulnPronoun := "it"
			if countRemainingFindings > 1 {
				vulnNoun = "vulnerabilities"
				vulnPronoun = "them"
			}

			wrapped.Println(fmt.Sprintf(
				"Alrighty then! We found %d %s in %s lacking a resolution in the advisory data. Let's take a look at %s.",
				countRemainingFindings,
				vulnNoun,
				styleBold.Render(bg.Origin.PkgInfo.Name),
				vulnPronoun,
			))

			fmt.Println()

			return nil
		},
	}

	opts.addToCmd(cmd)
	return cmd
}

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
		styleSubtle.Render(humanize.Time(bg.Origin.FileInfo.ModTime())),
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
		return fmt.Sprintf(welcomeMessageFormat, styleBold.Render("ctrl+C"))
	}()

	errorForNotADistroDirectory = func(cwd string) string {
		return fmt.Sprintf(
			notADistroDirectoryMessageFormat,
			styleBold.Render(cwd),
			styleBold.Copy().Italic(true).Render("is"),
		)
	}

	styleBoldItalic = lipgloss.NewStyle().Bold(true).Italic(true)
)
