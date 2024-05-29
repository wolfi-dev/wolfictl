package matchwatcher

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/savioxavier/termlink"
	"github.com/wolfi-dev/wolfictl/pkg/cli/styles"
	"github.com/wolfi-dev/wolfictl/pkg/vuln"
)

var _ tea.Model = (*Model)(nil)

var (
	helpKeyStyle         = styles.FaintAccent().Bold(true)
	helpExplanationStyle = styles.Faint()

	styleSubtle = lipgloss.NewStyle().Foreground(lipgloss.Color("#999999"))

	styleNegligible = lipgloss.NewStyle().Foreground(lipgloss.Color("#999999"))
	styleLow        = lipgloss.NewStyle().Foreground(lipgloss.Color("#00ff00"))
	styleMedium     = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffff00"))
	styleHigh       = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff9900"))
	styleCritical   = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff0000"))
)

func New(vulnEvents chan interface{}, countTotalPackages int) Model {
	return Model{
		vulnEvents:         vulnEvents,
		countTotalPackages: countTotalPackages,
		spinner: spinner.New(
			spinner.WithSpinner(spinner.Points),
			spinner.WithStyle(styles.Faint()),
		),
	}
}

type Model struct {
	// Err is an output the Model can return if something goes wrong.
	Err error

	vulnEvents         <-chan interface{}
	countTotalPackages int

	countPassedPackages int
	countFailedPackages int

	packages        []string
	packageStateMap map[string]packageState

	showEveryVulnerability bool

	exiting bool

	spinner spinner.Model
}

type packageState struct {
	name         string
	searching    bool
	matchesFound []vuln.Match
}

func (m Model) appendPackage(ps packageState) Model {
	if m.packageStateMap == nil {
		m.packageStateMap = make(map[string]packageState)
	}

	m.packages = append(m.packages, ps.name)
	m.packageStateMap[ps.name] = ps
	return m
}

func (m Model) updatePackage(ps packageState) Model {
	if m.packageStateMap == nil {
		m.packageStateMap = make(map[string]packageState)
	}

	m.packageStateMap[ps.name] = ps
	return m
}

func (m Model) removePackage(name string) Model {
	if m.packageStateMap == nil {
		m.packageStateMap = make(map[string]packageState)
	}

	delete(m.packageStateMap, name)
	for i, pkg := range m.packages {
		if pkg == name {
			m.packages = append(m.packages[:i], m.packages[i+1:]...)
			break
		}
	}
	return m
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.processNextEventCmd(),
		m.spinner.Tick,
	)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			m.exiting = true
			return m, tea.Quit

		case "v":
			if m.showEveryVulnerability {
				m.showEveryVulnerability = false
			} else {
				m.showEveryVulnerability = true
			}
			return m, nil

		default:
			return m, nil
		}

	case packageState:
		if msg.searching {
			return m.appendPackage(msg), m.processNextEventCmd()
		}

		// If the scan was clean, we don't need to show the package anymore.
		if len(msg.matchesFound) == 0 {
			m.countPassedPackages++
			m = m.removePackage(msg.name)
		} else {
			m.countFailedPackages++
			m = m.updatePackage(msg)
		}

		return m, m.processNextEventCmd()

	case errMsg:
		m.Err = msg.err
		return m, tea.Quit

	case doneMsg:
		m.exiting = true
		return m, tea.Quit

	default:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
}

func (m Model) processNextEventCmd() tea.Cmd {
	return func() tea.Msg {
		// TODO: make this preempt-able
		if m.vulnEvents == nil {
			return nil
		}

		e := <-m.vulnEvents
		switch e := e.(type) {
		case vuln.EventPackageMatchingStarting:
			return packageState{
				name:      e.Package,
				searching: true,
			}

		case vuln.EventPackageMatchingFinished:
			return packageState{
				name:         e.Package,
				searching:    false,
				matchesFound: e.Matches,
			}

		case vuln.EventPackageMatchingError:
			return errMsg{
				err: e.Err,
			}

		case vuln.EventMatchingFinished:
			return doneMsg{}
		}

		return nil
	}
}

// doneMsg is a message that is sent when the matching reporter is done.
type doneMsg struct{}

type errMsg struct {
	err error
}

func (m Model) View() string {
	// Summary

	viewSummary := styles.Secondary().Render(fmt.Sprintf(
		"%d clean, %d vulnerable, %d remaining",
		m.countPassedPackages,
		m.countFailedPackages,
		m.countTotalPackages-m.countPassedPackages-m.countFailedPackages,
	))

	// Package list

	var searchingPackageRows []string
	var vulnerablePackageRows []string

	for _, pkg := range m.packages {
		state := m.packageStateMap[pkg]

		if state.searching {
			msg := fmt.Sprintf(
				"%s %s %s",
				m.spinner.View(),
				styles.Secondary().Render("searching for vulnerabilities:"),
				pkg,
			)
			searchingPackageRows = append(searchingPackageRows, msg)

			continue
		}

		vulnCount := len(state.matchesFound)
		if vulnCount == 0 {
			continue
		}

		if m.showEveryVulnerability {
			row := strings.Builder{}
			fmt.Fprintf(&row, "%s", pkg)

			for i := range state.matchesFound {
				match := state.matchesFound[i]
				severity := ""
				if match.Vulnerability.Severity != "" {
					severity = renderSeverity(match.Vulnerability.Severity) + " "
				}
				fmt.Fprintf(&row, "\n  %s%s", severity, styleSubtle.Render(hyperlinkCVE(match.Vulnerability.ID)))
			}

			vulnerablePackageRows = append(vulnerablePackageRows, row.String())
			continue
		}

		vulnsWord := "vulnerability"
		if vulnCount != 1 {
			vulnsWord = "vulnerabilities"
		}

		row := fmt.Sprintf(
			"%s: %s",
			pkg,
			styles.Accented().Render(fmt.Sprintf("%d new %s", vulnCount, vulnsWord)),
		)
		vulnerablePackageRows = append(vulnerablePackageRows, row)
	}

	viewSearchingPackages := strings.Join(searchingPackageRows, "\n")
	viewVulnerablePackages := strings.Join(vulnerablePackageRows, "\n")

	// Help text (only if there are vulnerabilities)
	viewHelp := ""
	if m.countFailedPackages > 0 {
		action := "expand"
		if m.showEveryVulnerability {
			action = "collapse"
		}

		viewHelp = fmt.Sprintf("%s%s",
			helpKeyStyle.Render("v"),
			helpExplanationStyle.Render(" to "+action+" vulnerabilities"),
		)
	}

	// Put it all together

	if viewSearchingPackages != "" {
		viewSearchingPackages += "\n\n"
	}

	if viewVulnerablePackages != "" {
		viewVulnerablePackages += "\n\n"
	}

	if m.exiting {
		return fmt.Sprintf(
			"%s%s",
			viewVulnerablePackages,
			viewSummary+"\n",
		)
	}

	return fmt.Sprintf(
		"%s%s%s%s",
		viewSearchingPackages,
		viewVulnerablePackages,
		viewSummary+"\n",
		viewHelp+"\n",
	)
}

var termSupportsHyperlinks = termlink.SupportsHyperlinks()

func hyperlinkCVE(id string) string {
	if !termSupportsHyperlinks {
		return id
	}

	return termlink.Link(id, fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", id))
}

func renderSeverity(severity vuln.Severity) string {
	s := string(severity)

	switch severity {
	case vuln.SeverityLow:
		return styleLow.Render(s)
	case vuln.SeverityMedium:
		return styleMedium.Render(s)
	case vuln.SeverityHigh:
		return styleHigh.Render(s)
	case vuln.SeverityCritical:
		return styleCritical.Render(s)
	default:
		return styleNegligible.Render(s)
	}
}
